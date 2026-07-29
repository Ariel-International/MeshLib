/*
 * test_router.c — L3 topology + routing tests for the MeshLib C core.
 *
 * Covers: topology merge across a 4-node chain, BFS next-hop matching the
 * expected first hop on each path, on_route deliver-to-self vs forward,
 * malformed from/to dropped WITHOUT tearing the link down
 * (../../WIRE_FORMAT.md:119-121), send with and without a known route, and
 * depth() for self / direct / multi-hop / unknown peers.
 *
 * Port reference: Java MeshRouter + MeshTopology (src/main/java/com/mesh/).
 *
 * Peer ids here are short valid-hex stand-ins, not real X.509 DER keys — L3
 * only ever treats a PeerId as an opaque strict-hex string, so a real 91-byte
 * key would make the expectations unreadable for no added coverage.
 *
 * No framework — plain checks with a pass/fail tally. Exit 0 = all pass.
 */
#include "mesh_router.h"
#include "mesh_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (cond) { g_pass++; }                                                 \
        else { g_fail++; printf("  FAIL  %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

/* Four nodes, A—B—C—D (a chain), so a next hop is unambiguous at every step. */
#define A "aa01"
#define B "bb02"
#define C "cc03"
#define D "dd04"

/* ---- capture harness ---------------------------------------------------- */

#define MAX_CAP 32

typedef struct {
    char  hop[64];
    char  frame[1024];
} sent_t;

typedef struct {
    sent_t sent[MAX_CAP];
    int    sent_count;

    char   deliver_from[64];
    char   deliver_payload[1024];
    int    deliver_count;

    mesh_result_t send_rc;      /* what on_send reports back */
} cap_t;

static void cap_reset(cap_t *c) {
    memset(c, 0, sizeof(*c));
    c->send_rc = MESH_OK;
}

static mesh_result_t on_send(const char *next_hop_hex, mesh_bytes_t frame, void *user) {
    cap_t *c = (cap_t *)user;
    if (c->sent_count < MAX_CAP) {
        sent_t *s = &c->sent[c->sent_count];
        snprintf(s->hop, sizeof(s->hop), "%s", next_hop_hex ? next_hop_hex : "(null)");
        size_t n = frame.len < sizeof(s->frame) - 1 ? frame.len : sizeof(s->frame) - 1;
        memcpy(s->frame, frame.data, n);
        s->frame[n] = '\0';
        c->sent_count++;
    }
    return c->send_rc;
}

static void on_deliver(const char *from_hex, mesh_bytes_t payload, void *user) {
    cap_t *c = (cap_t *)user;
    snprintf(c->deliver_from, sizeof(c->deliver_from), "%s", from_hex ? from_hex : "(null)");
    size_t n = payload.len < sizeof(c->deliver_payload) - 1
             ? payload.len : sizeof(c->deliver_payload) - 1;
    memcpy(c->deliver_payload, payload.data, n);
    c->deliver_payload[n] = '\0';
    c->deliver_count++;
}

/* Did we send anything to `hop`? Returns the frame, or NULL. */
static const char *sent_to(const cap_t *c, const char *hop) {
    for (int i = 0; i < c->sent_count; i++)
        if (strcmp(c->sent[i].hop, hop) == 0) return c->sent[i].frame;
    return NULL;
}

static mesh_bytes_t str_bytes(const char *s) {
    mesh_bytes_t b = { (const uint8_t *)s, strlen(s) };
    return b;
}

/* ---- creation ----------------------------------------------------------- */

static void test_create(void) {
    printf("== create / free ==\n");
    cap_t cap; cap_reset(&cap);
    mesh_router_t *r = NULL;

    mesh_result_t rc = mesh_router_create(A, on_send, on_deliver, &cap, &r);
    CHECK(rc == MESH_OK && r != NULL, "create with valid self hex");

    int depth = -1;
    CHECK(mesh_router_depth(r, A, &depth) == MESH_OK && depth == 0, "self depth is 0");
    mesh_router_free(r);

    r = NULL;
    CHECK(mesh_router_create("zz", on_send, on_deliver, &cap, &r) == MESH_ERR_MALFORMED,
          "create rejects non-hex self id");
    CHECK(r == NULL, "rejected create leaves out NULL");
    CHECK(mesh_router_create(NULL, on_send, on_deliver, &cap, &r) == MESH_ERR_INVALID_ARG,
          "create rejects NULL self id");
    mesh_router_free(NULL);  /* must be a no-op, not a crash */
    g_pass++;                /* survived free(NULL) */
}

/* ---- link up/down floods ------------------------------------------------ */

static void test_link_flood(void) {
    printf("== link_up / link_down flood topology ==\n");
    cap_t cap; cap_reset(&cap);
    mesh_router_t *r = NULL;
    mesh_router_create(A, on_send, on_deliver, &cap, &r);

    CHECK(mesh_router_link_up(r, B) == MESH_OK, "link_up accepted");
    CHECK(cap.sent_count == 1, "link_up floods once (to the one neighbour)");
    const char *f = sent_to(&cap, B);
    CHECK(f != NULL, "flood addressed to the new neighbour");
    CHECK(f && strstr(f, "\"type\":\"topology\"") != NULL, "flood is a topology frame");
    CHECK(f && strstr(f, "\"peer\":\"" A "\"") != NULL, "flood advertises self as peer");
    CHECK(f && strstr(f, "\"" B "\"") != NULL, "flood lists the new neighbour");

    int depth = -1;
    CHECK(mesh_router_depth(r, B, &depth) == MESH_OK && depth == 1, "direct neighbour depth 1");

    /* Second link: both neighbours get the updated view. */
    cap_reset(&cap);
    mesh_router_link_up(r, C);
    CHECK(cap.sent_count == 2, "second link_up floods to both neighbours");
    CHECK(sent_to(&cap, B) != NULL && sent_to(&cap, C) != NULL, "flood reaches B and C");

    /* link_down drops the edge and floods to the peers that remain. */
    cap_reset(&cap);
    CHECK(mesh_router_link_down(r, B) == MESH_OK, "link_down accepted");
    CHECK(mesh_router_depth(r, B, &depth) == MESH_ERR_MALFORMED,
          "dropped peer is unreachable again");
    CHECK(sent_to(&cap, B) == NULL, "downed peer is not a flood target");
    CHECK(sent_to(&cap, C) != NULL, "remaining peer still gets the flood");

    CHECK(mesh_router_link_up(r, "nothex") == MESH_ERR_MALFORMED,
          "link_up rejects malformed peer hex");
    CHECK(mesh_router_link_up(r, A) == MESH_ERR_INVALID_ARG, "link_up rejects self");

    mesh_router_free(r);
}

/* ---- topology merge across 4 nodes -------------------------------------- */

/*
 * Builds A's view of the chain A—B—C—D: A holds a real link to B, then learns
 * B's and C's rows by flood. Leaves `cap` holding whatever the last merge sent.
 */
static mesh_router_t *build_chain(cap_t *cap) {
    mesh_router_t *r = NULL;
    mesh_router_create(A, on_send, on_deliver, cap, &r);
    mesh_router_link_up(r, B);
    /* B says: I know A and C. */
    mesh_router_on_topology(r, str_bytes(
        "{\"type\":\"topology\",\"peer\":\"" B "\",\"neighbors\":[\"" A "\",\"" C "\"]}"));
    /* C says: I know B and D. */
    mesh_router_on_topology(r, str_bytes(
        "{\"type\":\"topology\",\"peer\":\"" C "\",\"neighbors\":[\"" B "\",\"" D "\"]}"));
    return r;
}

static void test_topology_merge(void) {
    printf("== topology merge across 4 nodes ==\n");
    cap_t cap; cap_reset(&cap);
    mesh_router_t *r = build_chain(&cap);

    int depth = -1;
    CHECK(mesh_router_depth(r, B, &depth) == MESH_OK && depth == 1, "depth(B) == 1");
    CHECK(mesh_router_depth(r, C, &depth) == MESH_OK && depth == 2, "depth(C) == 2");
    CHECK(mesh_router_depth(r, D, &depth) == MESH_OK && depth == 3, "depth(D) == 3");
    CHECK(mesh_router_depth(r, "ff09", &depth) == MESH_ERR_MALFORMED,
          "depth of an unknown peer is an error");
    CHECK(depth == -1, "unknown peer leaves out_depth at -1");
    CHECK(mesh_router_depth(r, "nothex", &depth) == MESH_ERR_MALFORMED,
          "depth rejects malformed hex");

    /* A changed view re-floods; an identical repeat still floods (so the
     * sender learns our row) but must not disturb the graph. */
    cap_reset(&cap);
    mesh_result_t rc = mesh_router_on_topology(r, str_bytes(
        "{\"type\":\"topology\",\"peer\":\"" C "\",\"neighbors\":[\"" B "\",\"" D "\"]}"));
    CHECK(rc == MESH_OK, "repeat of a known row is accepted");
    CHECK(sent_to(&cap, C) == NULL, "re-flood excludes the reporting peer");
    CHECK(mesh_router_depth(r, D, &depth) == MESH_OK && depth == 3,
          "repeat leaves the graph unchanged");

    /* Shrinking a row is authoritative: C drops D, so D goes unreachable. */
    mesh_router_on_topology(r, str_bytes(
        "{\"type\":\"topology\",\"peer\":\"" C "\",\"neighbors\":[\"" B "\"]}"));
    CHECK(mesh_router_depth(r, D, &depth) == MESH_ERR_MALFORMED,
          "a shrunk row makes the orphan unreachable");

    mesh_router_free(r);

    /* Malformed topology frames are rejected wholesale. */
    printf("== topology merge rejects malformed frames ==\n");
    cap_reset(&cap);
    mesh_router_create(A, on_send, on_deliver, &cap, &r);
    mesh_router_link_up(r, B);

    CHECK(mesh_router_on_topology(r, str_bytes(
              "{\"type\":\"topology\",\"neighbors\":[\"" A "\"]}")) == MESH_ERR_MALFORMED,
          "topology without a peer field is rejected");
    CHECK(mesh_router_on_topology(r, str_bytes(
              "{\"type\":\"topology\",\"peer\":\"" C "\"}")) == MESH_ERR_MALFORMED,
          "topology without neighbors is rejected");
    CHECK(mesh_router_on_topology(r, str_bytes(
              "{\"type\":\"topology\",\"peer\":\"zzzz\",\"neighbors\":[]}")) == MESH_ERR_MALFORMED,
          "topology with non-hex peer is rejected");
    CHECK(mesh_router_on_topology(r, str_bytes(
              "{\"type\":\"topology\",\"peer\":\"" C "\",\"neighbors\":[\"" D "\",\"oops\"]}"))
              == MESH_ERR_MALFORMED,
          "one bad neighbour rejects the whole row");
    CHECK(mesh_router_depth(r, D, &depth) == MESH_ERR_MALFORMED,
          "rejected row is not partially merged");

    /* An empty neighbour list is legal — an isolated node advertising itself. */
    CHECK(mesh_router_on_topology(r, str_bytes(
              "{\"type\":\"topology\",\"peer\":\"" C "\",\"neighbors\":[]}")) == MESH_OK,
          "empty neighbors array is accepted");

    mesh_router_free(r);
}

/* ---- next hop via on_route forwarding ----------------------------------- */

static void test_on_route(void) {
    printf("== on_route: deliver to self vs forward ==\n");
    cap_t cap; cap_reset(&cap);
    mesh_router_t *r = build_chain(&cap);

    /* to == self: delivered locally, nothing forwarded. */
    cap_reset(&cap);
    mesh_result_t rc = mesh_router_on_route(r, str_bytes(
        "{\"type\":\"route\",\"from\":\"" D "\",\"to\":\"" A "\","
        "\"payload\":{\"layer\":\"message\",\"text\":\"hi\"}}"));
    CHECK(rc == MESH_OK, "route addressed to self is accepted");
    CHECK(cap.deliver_count == 1, "route to self delivers exactly once");
    CHECK(strcmp(cap.deliver_from, D) == 0, "deliver reports the originator");
    CHECK(strcmp(cap.deliver_payload,
                 "{\"layer\":\"message\",\"text\":\"hi\"}") == 0,
          "payload delivered verbatim");
    CHECK(cap.sent_count == 0, "route to self is not forwarded");

    /* to == D: forwarded toward B (the only first hop on A—B—C—D). */
    cap_reset(&cap);
    const char *fwd = "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"" D "\","
                      "\"payload\":{\"n\":1}}";
    rc = mesh_router_on_route(r, str_bytes(fwd));
    CHECK(rc == MESH_OK, "route to a reachable peer is accepted");
    CHECK(cap.deliver_count == 0, "forwarded route is not delivered locally");
    CHECK(cap.sent_count == 1, "forwarded route is sent once");
    CHECK(cap.sent_count == 1 && strcmp(cap.sent[0].hop, B) == 0,
          "next hop toward D is B (BFS first hop)");
    CHECK(cap.sent_count == 1 && strcmp(cap.sent[0].frame, fwd) == 0,
          "forwarded frame is byte-identical to the received one");

    /* to == C: also via B — the chain gives one first hop for both. */
    cap_reset(&cap);
    mesh_router_on_route(r, str_bytes(
        "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"" C "\",\"payload\":{}}"));
    CHECK(cap.sent_count == 1 && strcmp(cap.sent[0].hop, B) == 0, "next hop toward C is B");

    /* Unknown destination: dropped, nothing sent. */
    cap_reset(&cap);
    rc = mesh_router_on_route(r, str_bytes(
        "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"ff09\",\"payload\":{}}"));
    CHECK(rc == MESH_ERR_MALFORMED, "route to an unknown peer is dropped");
    CHECK(cap.sent_count == 0 && cap.deliver_count == 0, "unroutable frame goes nowhere");

    mesh_router_free(r);
}

/* ---- malformed route frames: drop, keep the link up --------------------- */

static void test_on_route_malformed(void) {
    printf("== on_route: malformed from/to dropped without teardown ==\n");
    cap_t cap; cap_reset(&cap);
    mesh_router_t *r = build_chain(&cap);
    cap_reset(&cap);

    struct { const char *json; const char *what; } bad[] = {
        { "{\"type\":\"route\",\"from\":\"zzzz\",\"to\":\"" D "\",\"payload\":{}}",
          "non-hex from" },
        { "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"zzzz\",\"payload\":{}}",
          "non-hex to" },
        { "{\"type\":\"route\",\"from\":\"aa0\",\"to\":\"" D "\",\"payload\":{}}",
          "odd-length from" },
        { "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"dd0\",\"payload\":{}}",
          "odd-length to" },
        { "{\"type\":\"route\",\"to\":\"" D "\",\"payload\":{}}",
          "missing from" },
        { "{\"type\":\"route\",\"from\":\"" A "\",\"payload\":{}}",
          "missing to" },
        { "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"" D "\"}",
          "missing payload" },
        { "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"" A "\",\"payload\":\"nope\"}",
          "payload is not an object" },
        { "{\"type\":\"route\",\"from\":\"\",\"to\":\"" D "\",\"payload\":{}}",
          "empty from" },
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mesh_result_t rc = mesh_router_on_route(r, str_bytes(bad[i].json));
        CHECK(rc == MESH_ERR_MALFORMED, bad[i].what);
    }
    CHECK(cap.sent_count == 0, "no malformed frame was forwarded");
    CHECK(cap.deliver_count == 0, "no malformed frame was delivered");

    /*
     * WIRE_FORMAT.md:119-121 — the link stays up. The router holds no link
     * state to tear down, so the observable contract is that the graph is
     * untouched and the very next well-formed frame still routes.
     */
    int depth = -1;
    CHECK(mesh_router_depth(r, B, &depth) == MESH_OK && depth == 1,
          "graph intact after malformed frames (B still direct)");
    CHECK(mesh_router_depth(r, D, &depth) == MESH_OK && depth == 3,
          "graph intact after malformed frames (D still 3 hops)");

    cap_reset(&cap);
    mesh_result_t rc = mesh_router_on_route(r, str_bytes(
        "{\"type\":\"route\",\"from\":\"" A "\",\"to\":\"" D "\",\"payload\":{\"ok\":1}}"));
    CHECK(rc == MESH_OK && cap.sent_count == 1 && strcmp(cap.sent[0].hop, B) == 0,
          "link still usable: next good frame routes normally");

    mesh_router_free(r);
}

/* ---- originating sends -------------------------------------------------- */

static void test_send(void) {
    printf("== send ==\n");
    cap_t cap; cap_reset(&cap);
    mesh_router_t *r = build_chain(&cap);
    cap_reset(&cap);

    const char *payload = "{\"layer\":\"session\",\"id\":7}";
    mesh_result_t rc = mesh_router_send(r, D, str_bytes(payload));
    CHECK(rc == MESH_OK, "send to a reachable peer succeeds");
    CHECK(cap.sent_count == 1 && strcmp(cap.sent[0].hop, B) == 0, "send goes to next hop B");

    const char *f = cap.sent_count ? cap.sent[0].frame : "";
    CHECK(strstr(f, "\"type\":\"route\"") != NULL, "frame is a route frame");
    CHECK(strstr(f, "\"from\":\"" A "\"") != NULL, "from is self");
    CHECK(strstr(f, "\"to\":\"" D "\"") != NULL, "to is the destination");
    CHECK(strstr(f, payload) != NULL, "payload embedded verbatim");

    /* No route known yet. */
    cap_reset(&cap);
    rc = mesh_router_send(r, "ff09", str_bytes(payload));
    CHECK(rc == MESH_ERR_MALFORMED, "send with no known route returns MESH_ERR_MALFORMED");
    CHECK(cap.sent_count == 0, "unroutable send emits nothing");

    /* Send to self short-circuits to local delivery (Java MeshRouter.send). */
    cap_reset(&cap);
    rc = mesh_router_send(r, A, str_bytes(payload));
    CHECK(rc == MESH_OK, "send to self succeeds");
    CHECK(cap.deliver_count == 1 && cap.sent_count == 0, "send to self delivers locally only");

    CHECK(mesh_router_send(r, "nothex", str_bytes(payload)) == MESH_ERR_MALFORMED,
          "send rejects malformed destination hex");
    CHECK(mesh_router_send(r, NULL, str_bytes(payload)) == MESH_ERR_INVALID_ARG,
          "send rejects NULL destination");

    /* A transport failure is reported to the caller, not swallowed. */
    cap_reset(&cap);
    cap.send_rc = MESH_ERR_IO;
    CHECK(mesh_router_send(r, D, str_bytes(payload)) == MESH_ERR_IO,
          "send propagates the transport error");

    mesh_router_free(r);
}

int main(void) {
    printf("mesh_router (L3) tests\n\n");
    test_create();
    test_link_flood();
    test_topology_merge();
    test_on_route();
    test_on_route_malformed();
    test_send();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
