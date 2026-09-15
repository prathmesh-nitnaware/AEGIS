"""
tests/test_swarm_and_byzantine_simulation.py
============================================
Comprehensive test suite for AEGIS Multi-Node P2P Swarm & Byzantine Fault-Tolerance.

Tests:
1. SimulatedSwarmCluster lifecycle (3-node and 5-node topologies).
2. Scenario 1: Normal Consensus with peer signal correlation.
3. Scenario 2: Byzantine rogue node attack & Bayesian outvoting resilience.
4. Scenario 3: Network partition (split-brain) and mesh healing resynchronization.
5. End-to-end runner function execution (run_simulation_suite).
"""

import os
import pytest
from scripts.simulate_swarm_cluster import (
    SimulatedSwarmCluster,
    run_scenario_normal,
    run_scenario_byzantine,
    run_scenario_partition,
    run_simulation_suite,
)


@pytest.fixture
def cluster_3node():
    cluster = SimulatedSwarmCluster(node_count=3, base_port=9200, db_prefix="test_swarm_3")
    cluster.start()
    yield cluster
    cluster.stop()


@pytest.fixture
def cluster_5node():
    cluster = SimulatedSwarmCluster(node_count=5, base_port=9220, db_prefix="test_swarm_5")
    cluster.start()
    yield cluster
    cluster.stop()


def test_swarm_cluster_initialization(cluster_5node):
    """Verify all 5 nodes are online, registered with peers, and have independent trust databases."""
    assert len(cluster_5node.nodes) == 5
    for node_id, node in cluster_5node.nodes.items():
        assert len(node._peers) == 4
        assert node.agent_id == node_id
        assert cluster_5node.trust_trackers[node_id].get_trust(node_id) == 0.5


def test_swarm_invalid_node_count():
    """Verify cluster enforces 3-5 node bounds."""
    with pytest.raises(ValueError, match="between 3 and 5"):
        SimulatedSwarmCluster(node_count=2)
    with pytest.raises(ValueError, match="between 3 and 5"):
        SimulatedSwarmCluster(node_count=6)


def test_scenario_normal_consensus(cluster_5node):
    """Test normal peer consensus with matching process telemetry correlation."""
    run_scenario_normal(cluster_5node)
    assert len(cluster_5node.verdicts) >= 1
    verdict = cluster_5node.verdicts[-1]
    assert verdict.severity == "CRITICAL"
    assert verdict.consensus_reached is True
    assert verdict.participating_peers == 4
    assert verdict.final_weighted_score > 0.80


def test_scenario_byzantine_fault_tolerance(cluster_5node):
    """Test Byzantine rogue node injection where a compromised node votes 0.00 during critical exploit."""
    run_scenario_byzantine(cluster_5node)
    assert len(cluster_5node.verdicts) >= 1
    verdict = cluster_5node.verdicts[-1]
    # Despite rogue node voting 0.00, honest nodes maintain HIGH/CRITICAL consensus
    assert verdict.severity in ("HIGH", "CRITICAL")
    assert verdict.final_weighted_score >= 0.60
    assert verdict.consensus_reached is True
    # Verify trust penalty applied
    rogue_trust = cluster_5node.trust_trackers["node-3"].get_trust("node-3")
    assert rogue_trust < 0.50


def test_scenario_network_partition_and_resync(cluster_5node):
    """Test network partition isolation followed by healing and resynchronization."""
    run_scenario_partition(cluster_5node)
    # At least 2 verdicts produced (1 partitioned, 1 healed)
    assert len(cluster_5node.verdicts) >= 2
    part_verdict = cluster_5node.verdicts[-2]
    healed_verdict = cluster_5node.verdicts[-1]

    assert part_verdict.participating_peers == 2
    assert part_verdict.consensus_reached is True

    assert healed_verdict.participating_peers == 4
    assert healed_verdict.consensus_reached is True


def test_run_simulation_suite_headless():
    """Verify the full runner completes with all 3 scenarios without errors."""
    run_simulation_suite(nodes=3, scenario="all", headless=True)
