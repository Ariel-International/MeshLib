/*
 * mesh_router.c — L3 topology + routing (portable core).
 *
 * Port target: Java MeshRouter + MeshTopology (src/main/java/com/mesh/). The
 * graph, merge semantics, BFS next-hop and depth map are a direct transcription
 * of MeshTopology; the frame shapes and dispatch are MeshRouter's.
 *
 * Wire shapes (as emitted by the Java reference):
 *   topology: {"type":"topology","peer":<hex>,"neighbors":[<hex>,...]}
 *   route:    {"type":"route","from":<hex>,"to":<hex>,"payload":{...}}
 *
 * Rules: ../../WIRE_FORMAT.md:94 (lowercase hex peer keys), :119-121 (a
 * malformed route frame is DROPPED and the error returned; the link stays up —
 * unlike the L2 handshake, which fails the link).
 *
 * Differences from the Java reference, forced by this API's shape:
 *  - The core owns no sockets and no timers. mesh_send_fn hands a finished frame
 *    to the embedder addressed by next-hop hex; the 3 s periodic re-flood in
 *    MeshRouter.mSyncLoop is the embedder's job (call mesh_router_link_up or let
 *    it drive its own timer).
 *  - mesh_router_on_topology receives no link handle, so the re-flood excludes
 *    the reporting peer by hex (`peer` field) rather than by link identity. Same
 *    effect: we never bounce a peer's own view straight back at it.
 */
#include "mesh_router.h"
#include "mesh_codec.h"

#include <stdlib.h>
#include <string.h>

/* A peer hex is a hex-encoded X.509 SubjectPublicKeyInfo DER (~91 bytes for
 * P-256 => ~182 chars). Cap generously but finitely: a peer hex arriving off
 * the wire is untrusted, and the graph is keyed by it. */
#define ROUTER_MAX_HEX_LEN 1024

/* ===================================================================== */
/*  Adjacency graph                                                      */
/*                                                                       */
/*  Java uses ConcurrentHashMap<String, Set<String>>. Here: a flat array  */
/*  of nodes, each owning a flat array of neighbour hex strings. Meshes   */
/*  this core targets are tens of nodes, not thousands — linear scan is   */
/*  cheaper than a hash table and has no allocator churn on lookup.       */
/*  Not thread-safe: the Java class is, but the C core is single-threaded */
/*  by contract (README.md) — the embedder owns the read thread.          */
/* ===================================================================== */

typedef struct {
    char  **items;      /* owned NUL-terminated hex strings */
    size_t  count;
    size_t  cap;
} hexset_t;

typedef struct {
    char     *peer;     /* owned hex key */
    hexset_t  neighbors;
} node_t;

struct mesh_router {
    char   *self_hex;   /* owned */

    node_t *nodes;
    size_t  node_count;
    size_t  node_cap;

    mesh_send_fn    on_send;
    mesh_deliver_fn on_deliver;
    void           *user;
};

/* ---- hexset ------------------------------------------------------------ */

static void hexset_free(hexset_t *s) {
    for (size_t i = 0; i < s->count; i++) free(s->items[i]);
    free(s->items);
    s->items = NULL;
    s->count = 0;
    s->cap = 0;
}

static int hexset_contains(const hexset_t *s, const char *hex) {
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->items[i], hex) == 0) return 1;
    return 0;
}

/* Adds `hex` if absent. Returns 1 if the set changed, 0 if already present,
 * -1 on allocation failure. */
static int hexset_add(hexset_t *s, const char *hex) {
    if (hexset_contains(s, hex)) return 0;
    if (s->count == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 4;
        char **ni = (char **)realloc(s->items, ncap * sizeof(*ni));
        if (!ni) return -1;
        s->items = ni;
        s->cap = ncap;
    }
    size_t len = strlen(hex);
    char *copy = (char *)malloc(len + 1);
    if (!copy) return -1;
    memcpy(copy, hex, len + 1);
    s->items[s->count++] = copy;
    return 1;
}

/* Removes `hex` if present. Returns 1 if the set changed. */
static int hexset_remove(hexset_t *s, const char *hex) {
    for (size_t i = 0; i < s->count; i++) {
        if (strcmp(s->items[i], hex) == 0) {
            free(s->items[i]);
            s->items[i] = s->items[s->count - 1];
            s->count--;
            return 1;
        }
    }
    return 0;
}

/* Set equality, order-independent (Java Set.equals). */
static int hexset_equals(const hexset_t *a, const hexset_t *b) {
    if (a->count != b->count) return 0;
    for (size_t i = 0; i < a->count; i++)
        if (!hexset_contains(b, a->items[i])) return 0;
    return 1;
}

/* ---- graph ------------------------------------------------------------- */

static node_t *graph_find(const mesh_router_t *r, const char *hex) {
    for (size_t i = 0; i < r->node_count; i++)
        if (strcmp(r->nodes[i].peer, hex) == 0) return &r->nodes[i];
    return NULL;
}

/* Java mComputeIfAbsent: returns the node for `hex`, creating an empty one if
 * needed. NULL only on allocation failure. */
static node_t *graph_get_or_create(mesh_router_t *r, const char *hex) {
    node_t *n = graph_find(r, hex);
    if (n) return n;

    if (r->node_count == r->node_cap) {
        size_t ncap = r->node_cap ? r->node_cap * 2 : 8;
        node_t *nn = (node_t *)realloc(r->nodes, ncap * sizeof(*nn));
        if (!nn) return NULL;
        r->nodes = nn;
        r->node_cap = ncap;
    }
    size_t len = strlen(hex);
    char *copy = (char *)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, hex, len + 1);

    node_t *slot = &r->nodes[r->node_count];
    slot->peer = copy;
    slot->neighbors.items = NULL;
    slot->neighbors.count = 0;
    slot->neighbors.cap = 0;
    r->node_count++;
    return slot;
}

/* ===================================================================== */
/*  Minimal JSON reading (flat frames only)                              */
/*                                                                       */
/*  mesh_link.c has an equivalent string-value extractor for handshake    */
/*  frames; both are file-static by design (no cross-TU JSON API is part  */
/*  of the public core). L3 needs two shapes L2 does not: a string ARRAY  */
/*  (neighbors) and a raw nested OBJECT passed through verbatim           */
/*  (payload), so the scanner here is value-type aware.                   */
/* ===================================================================== */

static int is_ws(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/*
 * Locate the value of top-level key `key`. On success sets *val to the first
 * byte of the value token and returns MESH_OK; returns MESH_ERR_MALFORMED if
 * the key is absent or the object is unparseable, with *found = 0 when it was
 * simply absent.
 *
 * Same key-position discipline as mesh_link.c's json_get_string: a candidate
 * "key" counts only when preceded (modulo whitespace) by '{' or ',', and any
 * string token that is not our key is skipped whole so its contents can never
 * be rescanned as a key.
 */
static mesh_result_t json_find_value(mesh_bytes_t json, const char *key,
                                     const uint8_t **val, int *found) {
    if (!json.data || !key || !val || !found) return MESH_ERR_INVALID_ARG;
    *found = 0;
    *val = NULL;

    size_t keylen = strlen(key);
    const uint8_t *p = json.data;
    const uint8_t *end = json.data + json.len;

    while (p < end) {
        if (*p != '"') { p++; continue; }

        const uint8_t *q = p;
        const uint8_t *k = p + 1;
        int is_key_match = ((size_t)(end - k) >= keylen) &&
                           memcmp(k, key, keylen) == 0 &&
                           (k + keylen < end) && k[keylen] == '"';

        const uint8_t *b = p;
        while (b > json.data && is_ws(*(b - 1))) b--;
        int in_key_pos = (b == json.data) ? 0 : (*(b - 1) == '{' || *(b - 1) == ',');

        if (is_key_match && in_key_pos) {
            const uint8_t *r = k + keylen + 1;
            while (r < end && is_ws(*r)) r++;
            if (r >= end || *r != ':') return MESH_ERR_MALFORMED;
            r++;
            while (r < end && is_ws(*r)) r++;
            if (r >= end) return MESH_ERR_MALFORMED;
            *val = r;
            *found = 1;
            return MESH_OK;
        }

        /* Skip this whole string token. */
        p = q + 1;
        while (p < end) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '"') { p++; break; }
            p++;
        }
    }
    return MESH_ERR_MALFORMED;
}

/*
 * Read a JSON string token starting at `p` (which must be the opening quote).
 * Writes the unescaped value into `out` as a NUL-terminated string (the NUL is
 * written but not counted in out->len) and advances *endp past the closing
 * quote. Escapes are decoded exactly as in mesh_link.c; \u is limited to ASCII
 * because every L3 string field is hex.
 */
static mesh_result_t json_read_string(const uint8_t *p, const uint8_t *end,
                                      mesh_buf_t *out, const uint8_t **endp) {
    if (p >= end || *p != '"') return MESH_ERR_MALFORMED;
    p++;
    out->len = 0;
    while (p < end) {
        unsigned char c = *p;
        if (c == '"') {
            mesh_result_t rc = mesh_buf_reserve(out, 1);
            if (rc != MESH_OK) return rc;
            out->data[out->len] = '\0';
            if (endp) *endp = p + 1;
            return MESH_OK;
        }
        if (c == '\\') {
            p++;
            if (p >= end) return MESH_ERR_MALFORMED;
            unsigned char e = *p;
            uint8_t decoded;
            switch (e) {
                case '"':  decoded = '"';  break;
                case '\\': decoded = '\\'; break;
                case '/':  decoded = '/';  break;
                case 'b':  decoded = '\b'; break;
                case 'f':  decoded = '\f'; break;
                case 'n':  decoded = '\n'; break;
                case 'r':  decoded = '\r'; break;
                case 't':  decoded = '\t'; break;
                case 'u': {
                    if ((size_t)(end - p) < 5) return MESH_ERR_MALFORMED;
                    int hv = 0;
                    for (int i = 1; i <= 4; i++) {
                        unsigned char hc = p[i];
                        int v;
                        if (hc >= '0' && hc <= '9') v = hc - '0';
                        else if (hc >= 'a' && hc <= 'f') v = hc - 'a' + 10;
                        else if (hc >= 'A' && hc <= 'F') v = hc - 'A' + 10;
                        else return MESH_ERR_MALFORMED;
                        hv = (hv << 4) | v;
                    }
                    if (hv > 0x7F) return MESH_ERR_MALFORMED;
                    decoded = (uint8_t)hv;
                    p += 4;
                    break;
                }
                default: return MESH_ERR_MALFORMED;
            }
            mesh_result_t rc = mesh_buf_reserve(out, 1);
            if (rc != MESH_OK) return rc;
            out->data[out->len++] = decoded;
            p++;
        } else if (c < 0x20) {
            return MESH_ERR_MALFORMED;   /* raw control char in a JSON string */
        } else {
            mesh_result_t rc = mesh_buf_reserve(out, 1);
            if (rc != MESH_OK) return rc;
            out->data[out->len++] = c;
            p++;
        }
    }
    return MESH_ERR_MALFORMED;           /* unterminated */
}

/* Convenience: find `key` and read it as a string value. */
static mesh_result_t json_get_string(mesh_bytes_t json, const char *key,
                                     mesh_buf_t *out, int *found) {
    const uint8_t *v = NULL;
    mesh_result_t rc = json_find_value(json, key, &v, found);
    if (rc != MESH_OK) return rc;
    if (*v != '"') return MESH_ERR_MALFORMED;
    return json_read_string(v, json.data + json.len, out, NULL);
}

/*
 * Read the array value of `key` as a set of hex strings. Rejects anything that
 * is not a well-formed array of strings. An empty array is valid (a node with
 * no neighbours).
 */
static mesh_result_t json_get_string_array(mesh_bytes_t json, const char *key,
                                           hexset_t *out, int *found) {
    const uint8_t *p = NULL;
    mesh_result_t rc = json_find_value(json, key, &p, found);
    if (rc != MESH_OK) return rc;

    const uint8_t *end = json.data + json.len;
    if (*p != '[') return MESH_ERR_MALFORMED;
    p++;

    mesh_buf_t item;
    mesh_buf_init(&item);
    rc = MESH_OK;

    while (p < end) {
        while (p < end && is_ws(*p)) p++;
        if (p < end && *p == ']') { p++; goto done; }

        rc = json_read_string(p, end, &item, &p);
        if (rc != MESH_OK) goto done;
        if (hexset_add(out, (const char *)item.data) < 0) {
            rc = MESH_ERR_NOBUF;
            goto done;
        }

        while (p < end && is_ws(*p)) p++;
        if (p < end && *p == ',') { p++; continue; }
        if (p < end && *p == ']') { p++; goto done; }
        rc = MESH_ERR_MALFORMED;         /* junk between elements */
        goto done;
    }
    rc = MESH_ERR_MALFORMED;             /* unterminated array */

done:
    mesh_buf_free(&item);
    return rc;
}

/*
 * Locate the raw, verbatim extent of the object value of `key`. Route payloads
 * are opaque to L3 — we must forward the exact bytes we received rather than
 * re-serialising them, so this returns a view INTO `json` spanning the balanced
 * braces. String contents (including braces inside them) are skipped correctly.
 */
static mesh_result_t json_get_raw_object(mesh_bytes_t json, const char *key,
                                         mesh_bytes_t *out, int *found) {
    const uint8_t *p = NULL;
    mesh_result_t rc = json_find_value(json, key, &p, found);
    if (rc != MESH_OK) return rc;

    const uint8_t *end = json.data + json.len;
    if (*p != '{') return MESH_ERR_MALFORMED;

    const uint8_t *start = p;
    int depth = 0;
    while (p < end) {
        unsigned char c = *p;
        if (c == '"') {
            p++;
            while (p < end) {
                if (*p == '\\') { p += 2; continue; }
                if (*p == '"') { p++; break; }
                p++;
            }
            continue;
        }
        if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) {
                out->data = start;
                out->len = (size_t)(p + 1 - start);
                return MESH_OK;
            }
        }
        p++;
    }
    return MESH_ERR_MALFORMED;           /* unbalanced */
}

/* ---- JSON writing ------------------------------------------------------ */

static mesh_result_t json_append_raw(mesh_buf_t *out, const char *s, size_t len) {
    mesh_result_t rc = mesh_buf_reserve(out, len);
    if (rc != MESH_OK) return rc;
    memcpy(out->data + out->len, s, len);
    out->len += len;
    return MESH_OK;
}

static mesh_result_t json_append_lit(mesh_buf_t *out, const char *s) {
    return json_append_raw(out, s, strlen(s));
}

/*
 * Append a quoted JSON string. L3 string fields are hex PeerIds, which we
 * validate before they ever reach the graph — but escape defensively anyway so
 * a hostile key can never break out of its quotes into the emitted frame.
 */
static mesh_result_t json_append_quoted(mesh_buf_t *out, const char *s) {
    size_t len = strlen(s);
    mesh_result_t rc = mesh_buf_reserve(out, len * 6 + 2);
    if (rc != MESH_OK) return rc;
    uint8_t *o = out->data + out->len;
    size_t w = 0;
    static const char HEX[] = "0123456789abcdef";
    o[w++] = '"';
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  o[w++] = '\\'; o[w++] = '"';  break;
            case '\\': o[w++] = '\\'; o[w++] = '\\'; break;
            case '\b': o[w++] = '\\'; o[w++] = 'b';  break;
            case '\f': o[w++] = '\\'; o[w++] = 'f';  break;
            case '\n': o[w++] = '\\'; o[w++] = 'n';  break;
            case '\r': o[w++] = '\\'; o[w++] = 'r';  break;
            case '\t': o[w++] = '\\'; o[w++] = 't';  break;
            default:
                if (c < 0x20) {
                    o[w++] = '\\'; o[w++] = 'u'; o[w++] = '0'; o[w++] = '0';
                    o[w++] = HEX[(c >> 4) & 0xF];
                    o[w++] = HEX[c & 0xF];
                } else {
                    o[w++] = (char)c;
                }
                break;
        }
    }
    o[w++] = '"';
    out->len += w;
    return MESH_OK;
}

/* ===================================================================== */
/*  Peer hex validation                                                  */
/* ===================================================================== */

/*
 * A peer hex off the wire must decode as strict hex (WIRE_FORMAT.md:94-110) —
 * we reuse mesh_hex_decode rather than hand-rolling the character class, so L3
 * and L2 accept exactly the same set of PeerIds. The decoded bytes are
 * discarded: the graph keys on the hex text, as the Java reference does.
 */
static mesh_result_t validate_peer_hex(const char *hex) {
    if (!hex) return MESH_ERR_MALFORMED;
    size_t len = strlen(hex);
    if (len == 0 || len > ROUTER_MAX_HEX_LEN) return MESH_ERR_MALFORMED;

    mesh_buf_t tmp;
    mesh_buf_init(&tmp);
    mesh_result_t rc = mesh_hex_decode(hex, &tmp);
    mesh_buf_free(&tmp);
    return rc;
}

/* ===================================================================== */
/*  Topology frame build + flood                                         */
/* ===================================================================== */

/* Java MeshTopology.toFrame(). */
static mesh_result_t build_topology_frame(const mesh_router_t *r, mesh_buf_t *out) {
    const node_t *self = graph_find(r, r->self_hex);
    mesh_result_t rc;

    out->len = 0;
    if ((rc = json_append_lit(out, "{\"type\":\"topology\",\"peer\":")) != MESH_OK) return rc;
    if ((rc = json_append_quoted(out, r->self_hex)) != MESH_OK) return rc;
    if ((rc = json_append_lit(out, ",\"neighbors\":[")) != MESH_OK) return rc;
    if (self) {
        for (size_t i = 0; i < self->neighbors.count; i++) {
            if (i && (rc = json_append_lit(out, ",")) != MESH_OK) return rc;
            if ((rc = json_append_quoted(out, self->neighbors.items[i])) != MESH_OK) return rc;
        }
    }
    return json_append_lit(out, "]}");
}

/*
 * Send `frame` to every direct link except `exclude_hex` (may be NULL) — the
 * C analogue of MeshRouter.mFloodTopology(exclude). Individual send failures
 * are swallowed: the Java reference logs and continues so one dead link cannot
 * stop the flood reaching the others.
 */
static void flood(mesh_router_t *r, mesh_bytes_t frame, const char *exclude_hex) {
    const node_t *self = graph_find(r, r->self_hex);
    if (!self || !r->on_send) return;

    /* Snapshot the neighbour list: on_send is embedder code and may re-enter
     * the router (e.g. a link_down on write failure), reallocating the set. */
    size_t count = self->neighbors.count;
    if (count == 0) return;
    char **snapshot = (char **)malloc(count * sizeof(*snapshot));
    if (!snapshot) return;
    for (size_t i = 0; i < count; i++) {
        size_t len = strlen(self->neighbors.items[i]);
        snapshot[i] = (char *)malloc(len + 1);
        if (snapshot[i]) memcpy(snapshot[i], self->neighbors.items[i], len + 1);
    }

    for (size_t i = 0; i < count; i++) {
        if (!snapshot[i]) continue;
        if (exclude_hex && strcmp(snapshot[i], exclude_hex) == 0) continue;
        (void)r->on_send(snapshot[i], frame, r->user);
    }
    for (size_t i = 0; i < count; i++) free(snapshot[i]);
    free(snapshot);
}

static void flood_topology(mesh_router_t *r, const char *exclude_hex) {
    mesh_buf_t frame;
    mesh_buf_init(&frame);
    if (build_topology_frame(r, &frame) == MESH_OK) {
        mesh_bytes_t view = { frame.data, frame.len };
        flood(r, view, exclude_hex);
    }
    mesh_buf_free(&frame);
}

/* ===================================================================== */
/*  BFS — Java MeshTopology.nextHop / depthMap                           */
/* ===================================================================== */

/*
 * First hop from self toward `target_hex`. Returns the neighbour hex to send
 * through (a pointer into the graph, valid until the graph is mutated), or NULL
 * if no path exists. Self as target returns self, matching Java.
 */
static const char *next_hop(const mesh_router_t *r, const char *target_hex) {
    if (strcmp(r->self_hex, target_hex) == 0) return r->self_hex;

    const node_t *self = graph_find(r, r->self_hex);
    if (!self || self->neighbors.count == 0) return NULL;

    /* Queue of {current, via} pairs, exactly as the Java String[2] queue. */
    size_t qcap = r->node_count + self->neighbors.count + 1;
    const char **qcur = (const char **)malloc(qcap * sizeof(*qcur));
    const char **qvia = (const char **)malloc(qcap * sizeof(*qvia));
    const char **visited = (const char **)malloc((r->node_count + 1) * sizeof(*visited));
    const char *result = NULL;
    if (!qcur || !qvia || !visited) goto out;

    size_t qhead = 0, qtail = 0, vcount = 0;
    visited[vcount++] = r->self_hex;
    for (size_t i = 0; i < self->neighbors.count && qtail < qcap; i++) {
        qcur[qtail] = self->neighbors.items[i];
        qvia[qtail] = self->neighbors.items[i];
        qtail++;
    }

    while (qhead < qtail) {
        const char *cur = qcur[qhead];
        const char *via = qvia[qhead];
        qhead++;

        int seen = 0;
        for (size_t i = 0; i < vcount; i++)
            if (strcmp(visited[i], cur) == 0) { seen = 1; break; }
        if (seen) continue;
        if (vcount <= r->node_count) visited[vcount++] = cur;

        if (strcmp(cur, target_hex) == 0) { result = via; goto out; }

        const node_t *n = graph_find(r, cur);
        if (!n) continue;
        for (size_t i = 0; i < n->neighbors.count; i++) {
            const char *cand = n->neighbors.items[i];
            int cand_seen = 0;
            for (size_t j = 0; j < vcount; j++)
                if (strcmp(visited[j], cand) == 0) { cand_seen = 1; break; }
            if (cand_seen) continue;
            if (qtail == qcap) {
                size_t ncap = qcap * 2;
                const char **nc = (const char **)realloc(qcur, ncap * sizeof(*nc));
                if (!nc) goto out;
                qcur = nc;
                const char **nv = (const char **)realloc(qvia, ncap * sizeof(*nv));
                if (!nv) goto out;
                qvia = nv;
                qcap = ncap;
            }
            qcur[qtail] = cand;
            qvia[qtail] = via;
            qtail++;
        }
    }

out:
    free(qcur);
    free(qvia);
    free(visited);
    return result;
}

/* ===================================================================== */
/*  Public API                                                           */
/* ===================================================================== */

mesh_result_t mesh_router_create(const char *self_peer_id_hex,
                                 mesh_send_fn on_send,
                                 mesh_deliver_fn on_deliver,
                                 void *user,
                                 mesh_router_t **out) {
    if (!self_peer_id_hex || !out) return MESH_ERR_INVALID_ARG;
    *out = NULL;

    /* Our own id is not wire input, but a caller that passes junk would poison
     * every frame we emit — reject it here rather than at first send. */
    if (validate_peer_hex(self_peer_id_hex) != MESH_OK) return MESH_ERR_MALFORMED;

    mesh_router_t *r = (mesh_router_t *)calloc(1, sizeof(*r));
    if (!r) return MESH_ERR_NOBUF;

    size_t len = strlen(self_peer_id_hex);
    r->self_hex = (char *)malloc(len + 1);
    if (!r->self_hex) { free(r); return MESH_ERR_NOBUF; }
    memcpy(r->self_hex, self_peer_id_hex, len + 1);

    r->on_send = on_send;
    r->on_deliver = on_deliver;
    r->user = user;

    /* Java seeds the graph with an empty self entry so toFrame()/BFS always
     * find it. */
    if (!graph_get_or_create(r, r->self_hex)) {
        free(r->self_hex);
        free(r);
        return MESH_ERR_NOBUF;
    }

    *out = r;
    return MESH_OK;
}

void mesh_router_free(mesh_router_t *r) {
    if (!r) return;
    for (size_t i = 0; i < r->node_count; i++) {
        free(r->nodes[i].peer);
        hexset_free(&r->nodes[i].neighbors);
    }
    free(r->nodes);
    free(r->self_hex);
    free(r);
}

mesh_result_t mesh_router_link_up(mesh_router_t *r, const char *remote_peer_id_hex) {
    if (!r || !remote_peer_id_hex) return MESH_ERR_INVALID_ARG;
    mesh_result_t rc = validate_peer_hex(remote_peer_id_hex);
    if (rc != MESH_OK) return rc;
    if (strcmp(remote_peer_id_hex, r->self_hex) == 0) return MESH_ERR_INVALID_ARG;

    /* Java MeshTopology.addLink: the edge is recorded in both directions. */
    node_t *self = graph_get_or_create(r, r->self_hex);
    node_t *remote = graph_get_or_create(r, remote_peer_id_hex);
    if (!self || !remote) return MESH_ERR_NOBUF;

    int a = hexset_add(&self->neighbors, remote_peer_id_hex);
    if (a < 0) return MESH_ERR_NOBUF;
    /* graph_get_or_create may have grown r->nodes; re-resolve before use. */
    self = graph_find(r, r->self_hex);
    remote = graph_find(r, remote_peer_id_hex);
    if (!self || !remote) return MESH_ERR_NOBUF;
    int b = hexset_add(&remote->neighbors, r->self_hex);
    if (b < 0) return MESH_ERR_NOBUF;

    /* Flood unconditionally, as MeshRouter.onLinkReady does — a re-announce of
     * an already-known link is how a peer that missed the first flood catches
     * up (it replaces the periodic sync thread the core does not own). */
    flood_topology(r, NULL);
    return MESH_OK;
}

mesh_result_t mesh_router_link_down(mesh_router_t *r, const char *remote_peer_id_hex) {
    if (!r || !remote_peer_id_hex) return MESH_ERR_INVALID_ARG;
    mesh_result_t rc = validate_peer_hex(remote_peer_id_hex);
    if (rc != MESH_OK) return rc;

    node_t *self = graph_find(r, r->self_hex);
    node_t *remote = graph_find(r, remote_peer_id_hex);
    if (self) hexset_remove(&self->neighbors, remote_peer_id_hex);
    if (remote) hexset_remove(&remote->neighbors, r->self_hex);

    /* Flood AFTER the edge is gone, so the downed peer is not in our neighbour
     * list and therefore not a flood target. */
    flood_topology(r, NULL);
    return MESH_OK;
}

mesh_result_t mesh_router_on_topology(mesh_router_t *r, mesh_bytes_t topo_json) {
    if (!r || (topo_json.len > 0 && !topo_json.data)) return MESH_ERR_INVALID_ARG;
    if (!topo_json.data || topo_json.len == 0) return MESH_ERR_MALFORMED;

    mesh_buf_t peer;
    mesh_buf_init(&peer);
    hexset_t incoming = { NULL, 0, 0 };
    mesh_result_t rc;
    int found = 0;

    rc = json_get_string(topo_json, "peer", &peer, &found);
    if (rc != MESH_OK) goto out;
    rc = validate_peer_hex((const char *)peer.data);
    if (rc != MESH_OK) goto out;

    rc = json_get_string_array(topo_json, "neighbors", &incoming, &found);
    if (rc != MESH_OK) goto out;

    /* Every advertised neighbour is untrusted hex that would become a graph
     * key. Reject the whole frame if any entry is malformed rather than
     * merging a partially-valid view (WIRE_FORMAT.md: never repair). */
    for (size_t i = 0; i < incoming.count; i++) {
        rc = validate_peer_hex(incoming.items[i]);
        if (rc != MESH_OK) goto out;
    }

    {
        const char *peer_hex = (const char *)peer.data;

        /* A peer does not get to rewrite our own adjacency list — ours is
         * ground truth for links we hold. (Java stores it, but only ever
         * receives its own row back as an echo.) */
        if (strcmp(peer_hex, r->self_hex) == 0) { rc = MESH_OK; goto out; }

        node_t *n = graph_get_or_create(r, peer_hex);
        if (!n) { rc = MESH_ERR_NOBUF; goto out; }

        if (hexset_equals(&n->neighbors, &incoming)) {
            /* Java: merge() returns false, but mFloodTopology(link) still runs
             * so the sender learns our view. Re-flood excluding the sender. */
            flood_topology(r, peer_hex);
            rc = MESH_OK;
            goto out;
        }

        /* Replace wholesale — the sender's view of its own row is authoritative
         * and supersedes ours (Java: existing.clear(); existing.addAll()). */
        hexset_free(&n->neighbors);
        n->neighbors = incoming;
        incoming.items = NULL;
        incoming.count = 0;
        incoming.cap = 0;

        /* Make sure every advertised endpoint exists as a node, so BFS can walk
         * through peers we have never heard from directly. */
        for (size_t i = 0; i < n->neighbors.count; i++) {
            const char *nb = n->neighbors.items[i];
            if (!graph_get_or_create(r, nb)) { rc = MESH_ERR_NOBUF; goto out; }
            /* graph_get_or_create can realloc r->nodes; n is now stale. */
            n = graph_find(r, peer_hex);
            if (!n) { rc = MESH_ERR_NOBUF; goto out; }
        }

        flood_topology(r, peer_hex);
        rc = MESH_OK;
    }

out:
    mesh_buf_free(&peer);
    hexset_free(&incoming);
    return rc;
}

mesh_result_t mesh_router_on_route(mesh_router_t *r, mesh_bytes_t route_json) {
    if (!r || (route_json.len > 0 && !route_json.data)) return MESH_ERR_INVALID_ARG;
    if (!route_json.data || route_json.len == 0) return MESH_ERR_MALFORMED;

    mesh_buf_t from, to;
    mesh_buf_init(&from);
    mesh_buf_init(&to);
    mesh_result_t rc;
    int found = 0;

    /*
     * WIRE_FORMAT.md:119-121 — every failure below returns MESH_ERR_MALFORMED
     * and drops the frame. None of them is a link-level fault, so the caller
     * keeps the link up; contrast mesh_link.c, where a bad handshake field
     * moves the handshake to FAILED.
     */
    rc = json_get_string(route_json, "from", &from, &found);
    if (rc != MESH_OK) { rc = MESH_ERR_MALFORMED; goto out; }
    rc = validate_peer_hex((const char *)from.data);
    if (rc != MESH_OK) { rc = MESH_ERR_MALFORMED; goto out; }

    rc = json_get_string(route_json, "to", &to, &found);
    if (rc != MESH_OK) { rc = MESH_ERR_MALFORMED; goto out; }
    rc = validate_peer_hex((const char *)to.data);
    if (rc != MESH_OK) { rc = MESH_ERR_MALFORMED; goto out; }

    {
        mesh_bytes_t payload = { NULL, 0 };
        rc = json_get_raw_object(route_json, "payload", &payload, &found);
        if (rc != MESH_OK) { rc = MESH_ERR_MALFORMED; goto out; }

        if (strcmp((const char *)to.data, r->self_hex) == 0) {
            if (r->on_deliver)
                r->on_deliver((const char *)from.data, payload, r->user);
            rc = MESH_OK;
            goto out;
        }

        /* Forward verbatim — the frame is re-sent byte for byte, so hop count
         * never alters the bytes the destination verifies. */
        const char *hop = next_hop(r, (const char *)to.data);
        if (!hop) { rc = MESH_ERR_MALFORMED; goto out; }
        if (r->on_send) {
            mesh_bytes_t view = { route_json.data, route_json.len };
            rc = r->on_send(hop, view, r->user);
        } else {
            rc = MESH_OK;
        }
    }

out:
    mesh_buf_free(&from);
    mesh_buf_free(&to);
    return rc;
}

mesh_result_t mesh_router_send(mesh_router_t *r,
                               const char *dest_peer_id_hex,
                               mesh_bytes_t payload) {
    if (!r || !dest_peer_id_hex) return MESH_ERR_INVALID_ARG;
    if (payload.len > 0 && !payload.data) return MESH_ERR_INVALID_ARG;
    if (!payload.data || payload.len == 0) return MESH_ERR_INVALID_ARG;

    mesh_result_t rc = validate_peer_hex(dest_peer_id_hex);
    if (rc != MESH_OK) return rc;

    /* Java MeshRouter.send: a send to self is a local delivery, not a frame. */
    if (strcmp(dest_peer_id_hex, r->self_hex) == 0) {
        if (r->on_deliver) r->on_deliver(r->self_hex, payload, r->user);
        return MESH_OK;
    }

    const char *hop = next_hop(r, dest_peer_id_hex);
    if (!hop) return MESH_ERR_MALFORMED;   /* no route yet — caller may retry */

    mesh_buf_t frame;
    mesh_buf_init(&frame);
    rc = json_append_lit(&frame, "{\"type\":\"route\",\"from\":");
    if (rc == MESH_OK) rc = json_append_quoted(&frame, r->self_hex);
    if (rc == MESH_OK) rc = json_append_lit(&frame, ",\"to\":");
    if (rc == MESH_OK) rc = json_append_quoted(&frame, dest_peer_id_hex);
    if (rc == MESH_OK) rc = json_append_lit(&frame, ",\"payload\":");
    /* The payload is already JSON — embedded verbatim, as Java's
     * JSONObject.put(payload) does. */
    if (rc == MESH_OK) rc = json_append_raw(&frame, (const char *)payload.data,
                                            payload.len);
    if (rc == MESH_OK) rc = json_append_lit(&frame, "}");

    if (rc == MESH_OK && r->on_send) {
        mesh_bytes_t view = { frame.data, frame.len };
        rc = r->on_send(hop, view, r->user);
    }
    mesh_buf_free(&frame);
    return rc;
}

mesh_result_t mesh_router_depth(const mesh_router_t *r,
                                const char *dest_peer_id_hex,
                                int *out_depth) {
    if (!r || !dest_peer_id_hex || !out_depth) return MESH_ERR_INVALID_ARG;
    *out_depth = -1;

    if (validate_peer_hex(dest_peer_id_hex) != MESH_OK) return MESH_ERR_MALFORMED;
    if (strcmp(dest_peer_id_hex, r->self_hex) == 0) { *out_depth = 0; return MESH_OK; }

    /* Java MeshTopology.depthMap(), evaluated for a single target. Unreachable
     * peers are simply absent from that map => MESH_ERR_MALFORMED here. */
    size_t n = r->node_count;
    const char **queue = (const char **)malloc((n + 1) * sizeof(*queue));
    int *depth = (int *)malloc((n + 1) * sizeof(*depth));
    mesh_result_t rc = MESH_ERR_MALFORMED;
    if (!queue || !depth) { rc = MESH_ERR_NOBUF; goto out; }

    {
        size_t head = 0, tail = 0;
        queue[tail] = r->self_hex;
        depth[tail] = 0;
        tail++;

        while (head < tail) {
            const char *cur = queue[head];
            int d = depth[head];
            head++;

            const node_t *node = graph_find(r, cur);
            if (!node) continue;
            for (size_t i = 0; i < node->neighbors.count; i++) {
                const char *nb = node->neighbors.items[i];
                int seen = 0;
                for (size_t j = 0; j < tail; j++)
                    if (strcmp(queue[j], nb) == 0) { seen = 1; break; }
                if (seen) continue;
                if (strcmp(nb, dest_peer_id_hex) == 0) {
                    *out_depth = d + 1;
                    rc = MESH_OK;
                    goto out;
                }
                if (tail <= n) {
                    queue[tail] = nb;
                    depth[tail] = d + 1;
                    tail++;
                }
            }
        }
    }

out:
    free(queue);
    free(depth);
    return rc;
}
