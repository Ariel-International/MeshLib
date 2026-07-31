/*
 * mesh_router.h — L3 topology and routing.
 *
 * C counterpart of the Java MeshRouter + MeshTopology. The router maintains an
 * adjacency graph keyed by PeerId hex (WIRE_FORMAT.md:94), floods topology on
 * link change, and computes next hops by BFS. Route frames carry "from"/"to"
 * hex fields whose decode is strict but non-fatal (WIRE_FORMAT.md:119-121: a
 * malformed frame is dropped, the link stays up).
 */
#ifndef MESH_ROUTER_H
#define MESH_ROUTER_H

#include "mesh_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mesh_router mesh_router_t;

/*
 * Callback the router invokes to hand a frame to the transport for a given
 * next-hop peer (identified by hex PeerId). The core never touches a socket;
 * the embedder's callback does the actual send. `user` is passed through from
 * mesh_router_create.
 */
typedef mesh_result_t (*mesh_send_fn)(const char *next_hop_hex,
                                      mesh_bytes_t frame,
                                      void *user);

/*
 * Callback for a frame that reached this node (to == self). `from_hex` is the
 * originator; `payload` is the inner JSON. This is the L3->L4 boundary — L4/L5
 * are per-consumer and live outside this core (ARCHITECTURE.md:224).
 */
typedef void (*mesh_deliver_fn)(const char *from_hex,
                                mesh_bytes_t payload,
                                void *user);

/*
 * Create a router for local node `self_peer_id_hex`. Frees with
 * mesh_router_free().
 */
mesh_result_t mesh_router_create(const char *self_peer_id_hex,
                                 mesh_send_fn on_send,
                                 mesh_deliver_fn on_deliver,
                                 void *user,
                                 mesh_router_t **out);

void mesh_router_free(mesh_router_t *r);

/* Register/drop a direct link. Triggers a topology reflood. */
mesh_result_t mesh_router_link_up(mesh_router_t *r, const char *remote_peer_id_hex);
mesh_result_t mesh_router_link_down(mesh_router_t *r, const char *remote_peer_id_hex);

/*
 * Feed an inbound topology-flood frame (adjacency list of some peer). Updates
 * the graph and may re-flood to other links via the send callback.
 */
mesh_result_t mesh_router_on_topology(mesh_router_t *r, mesh_bytes_t topo_json);

/*
 * Feed an inbound route frame. If to==self, invokes on_deliver; otherwise
 * forwards toward the next hop via on_send. A malformed from/to hex causes the
 * frame to be DROPPED (returns MESH_ERR_MALFORMED) without tearing down the
 * link — WIRE_FORMAT.md:119-121.
 */
mesh_result_t mesh_router_on_route(mesh_router_t *r, mesh_bytes_t route_json);

/*
 * Originate a unicast to `dest_peer_id_hex`. Wraps `payload` in a route frame
 * and sends toward the computed next hop. Returns MESH_ERR_MALFORMED if no
 * route is known (caller decides whether to retry after topology settles).
 */
mesh_result_t mesh_router_send(mesh_router_t *r,
                               const char *dest_peer_id_hex,
                               mesh_bytes_t payload);

/*
 * Hop depth from self to `dest_peer_id_hex` (self = 0, direct peer = 1, ...),
 * written to *out_depth. Returns MESH_ERR_MALFORMED if the peer is unknown.
 */
mesh_result_t mesh_router_depth(const mesh_router_t *r,
                                const char *dest_peer_id_hex,
                                int *out_depth);

#ifdef __cplusplus
}
#endif

#endif /* MESH_ROUTER_H */
