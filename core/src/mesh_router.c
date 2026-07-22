/*
 * mesh_router.c — L3 topology + routing. SKELETON: no real logic yet.
 *
 * Port target: Java MeshRouter + MeshTopology. Rules: ../../WIRE_FORMAT.md:94
 * (hex keys), :119-121 (malformed route frame => drop, keep link up).
 */
#include "mesh_router.h"

struct mesh_router {
    /* TODO: self hex, adjacency graph, link table, callbacks + user ptr.
     * Placeholder keeps the type complete. */
    int placeholder;
};

mesh_result_t mesh_router_create(const char *self_peer_id_hex,
                                 mesh_send_fn on_send,
                                 mesh_deliver_fn on_deliver,
                                 void *user,
                                 mesh_router_t **out) {
    (void)self_peer_id_hex;
    (void)on_send;
    (void)on_deliver;
    (void)user;
    (void)out;
    /* TODO: alloc, seed graph with self node. */
    return MESH_ERR_UNIMPLEMENTED;
}

void mesh_router_free(mesh_router_t *r) {
    (void)r;
    /* TODO: free graph + link table, then free(r). */
}

mesh_result_t mesh_router_link_up(mesh_router_t *r, const char *remote_peer_id_hex) {
    (void)r;
    (void)remote_peer_id_hex;
    /* TODO: add edge self<->remote, reflood topology. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_router_link_down(mesh_router_t *r, const char *remote_peer_id_hex) {
    (void)r;
    (void)remote_peer_id_hex;
    /* TODO: drop edge, reflood topology. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_router_on_topology(mesh_router_t *r, mesh_bytes_t topo_json) {
    (void)r;
    (void)topo_json;
    /* TODO: merge adjacency, re-flood to other links. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_router_on_route(mesh_router_t *r, mesh_bytes_t route_json) {
    (void)r;
    (void)route_json;
    /* TODO: parse from/to (strict hex; malformed => drop, keep link);
     * deliver if to==self else forward via on_send. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_router_send(mesh_router_t *r,
                               const char *dest_peer_id_hex,
                               mesh_bytes_t payload) {
    (void)r;
    (void)dest_peer_id_hex;
    (void)payload;
    /* TODO: wrap payload in route frame, send to computed next hop. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_router_depth(const mesh_router_t *r,
                                const char *dest_peer_id_hex,
                                int *out_depth) {
    (void)r;
    (void)dest_peer_id_hex;
    (void)out_depth;
    /* TODO: BFS depth from self. */
    return MESH_ERR_UNIMPLEMENTED;
}
