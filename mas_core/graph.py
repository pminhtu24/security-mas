from langgraph.graph import StateGraph, END
from .state import ScanState
from .nodes import (
    coordinator_node,
    sast_worker_node,
    sca_worker_node,
    aggregator_node
)

def create_scan_graph():
    workflow = StateGraph(ScanState)

    #================= Add nodes ==================
    workflow.add_node("coordinator", coordinator_node)
    workflow.add_node("sast_worker", sast_worker_node)
    workflow.add_node("sca_worker", sca_worker_node)
    workflow.add_node("aggregator", aggregator_node)

    #================ Define Flow =================
    workflow.set_entry_point("coordinator")

    # Coordinator -> SAST & SCA (PARALLEL)
    workflow.add_edge("coordinator", "sast_worker")
    workflow.add_edge("coordinator", "sca_worker")

    # SAST & SCA -> Aggregator
    workflow.add_edge("sast_worker", "aggregator")
    workflow.add_edge("sca_worker", "aggregator")

    # Aggregator -> End
    workflow.add_edge("aggregator", END)
    app = workflow.compile()
    return app
