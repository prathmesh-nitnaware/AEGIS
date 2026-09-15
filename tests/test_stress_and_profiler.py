import os
import pytest
from experiments.benchmarks.stress_test_collectors import SyntheticCollectorStressTest
from experiments.benchmarks.collector_profiler import CollectorHardwareProfiler


def test_synthetic_collector_stress_test():
    # Run a fast 0.2s 10,000 ev/s test in pytest
    test_runner = SyntheticCollectorStressTest(target_rate=10000, duration_seconds=0.2, num_threads=2)
    results = test_runner.run()
    
    assert results["total_generated"] > 0
    assert results["total_consumed"] > 0
    assert results["actual_throughput_eps"] > 0
    assert "p50" in results["latency_us"]
    assert "p99" in results["latency_us"]
    assert results["drop_rate_pct"] <= 10.0


def test_collector_hardware_profiler_userspace():
    profiler = CollectorHardwareProfiler()
    res = profiler.profile_userspace_polling(iterations=100)
    assert res["iterations"] == 100
    assert res["wall_clock_time_s"] >= 0
    assert res["estimated_cpu_overhead_pct"] >= 0



def test_collector_hardware_profiler_ebpf():
    profiler = CollectorHardwareProfiler()
    res = profiler.profile_ebpf_kernel_tracer(iterations=100)
    assert res["iterations"] == 100
    assert res["wall_clock_time_s"] >= 0
    assert res["estimated_cpu_overhead_pct"] <= 5.0


def test_collector_flamegraph_generation(tmp_path):
    profiler = CollectorHardwareProfiler()
    svg_path = str(tmp_path / "test_flamegraph.svg")
    res = profiler.run_full_benchmark(output_svg_path=svg_path)
    
    assert os.path.exists(svg_path)
    with open(svg_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "<svg" in content
    assert "AEGIS CPU Flamegraph" in content
    assert "efficiency_multiplier" in res
