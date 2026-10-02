import asyncio

from app.core.security import Role, role_at_least
from app.services import topology
from app.services.bus import EventBus
from app.services.simulation import SimulationSource


def _devices():
    specs = topology.build_devices(7)
    return [
        {"id": f"dev_{i}", "hostname": s.hostname, "ip": s.ip, "device_type": s.device_type}
        for i, s in enumerate(specs)
    ]


def test_topology_is_deterministic_and_addresses_unique():
    a, b = topology.build_devices(7), topology.build_devices(7)
    assert [(d.hostname, d.ip, d.mac) for d in a] == [(d.hostname, d.ip, d.mac) for d in b]
    assert len({d.ip for d in a}) == len(a) == 47


def test_simulation_emits_normalized_info_events_only():
    src = SimulationSource(_devices(), seed=7)
    events = [src.next_event() for _ in range(300)]
    assert {e["severity"] for e in events} == {"info"}  # the simulator never invents detections
    assert all(e["source"] == "simulation" and e["src_ip"] and e["dst_ip"] for e in events)
    assert len({e["event_type"] for e in events}) >= 5


def test_role_hierarchy():
    assert role_at_least("ADMIN", Role.ANALYST)
    assert role_at_least("ANALYST", Role.VIEWER)
    assert not role_at_least("VIEWER", Role.ANALYST)
    assert not role_at_least("garbage", Role.VIEWER)


def test_bus_drops_for_slow_consumers_instead_of_blocking():
    async def run():
        bus = EventBus(queue_size=2)
        async with bus.subscribe() as q:
            for i in range(5):
                bus.publish({"n": i})
            return [q.get_nowait()["n"], q.get_nowait()["n"]]

    assert asyncio.run(run()) == [3, 4]  # oldest dropped, newest kept
