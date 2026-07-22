/*
 * mesh_common.c — shared helpers.
 *
 * mesh_buf_* is implemented (the codec needs a working output buffer); the
 * rest of the core remains stubbed. See ../include/mesh_common.h and
 * ../../WIRE_FORMAT.md.
 */
#include "mesh_common.h"

#include <stdlib.h>
#include <string.h>

void mesh_buf_init(mesh_buf_t *buf) {
    if (!buf) return;
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

mesh_result_t mesh_buf_reserve(mesh_buf_t *buf, size_t additional) {
    if (!buf) return MESH_ERR_INVALID_ARG;

    /* Guard against size_t overflow in len + additional. */
    if (additional > (size_t)-1 - buf->len) return MESH_ERR_TOO_LARGE;

    size_t needed = buf->len + additional;
    if (needed <= buf->cap) return MESH_OK;

    /* Grow geometrically (x2) but jump straight to `needed` if that is larger,
     * so a single large reserve does not need repeated doublings. */
    size_t new_cap = buf->cap ? buf->cap : 16;
    while (new_cap < needed) {
        if (new_cap > ((size_t)-1) / 2) { new_cap = needed; break; }
        new_cap *= 2;
    }

    uint8_t *p = (uint8_t *)realloc(buf->data, new_cap);
    if (!p) return MESH_ERR_NOBUF;
    buf->data = p;
    buf->cap  = new_cap;
    return MESH_OK;
}

void mesh_buf_free(mesh_buf_t *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

const char *mesh_result_str(mesh_result_t rc) {
    switch (rc) {
        case MESH_OK:                 return "MESH_OK";
        case MESH_ERR_INVALID_ARG:    return "MESH_ERR_INVALID_ARG";
        case MESH_ERR_MALFORMED:      return "MESH_ERR_MALFORMED";
        case MESH_ERR_TOO_LARGE:      return "MESH_ERR_TOO_LARGE";
        case MESH_ERR_NOBUF:          return "MESH_ERR_NOBUF";
        case MESH_ERR_CRYPTO:         return "MESH_ERR_CRYPTO";
        case MESH_ERR_IO:             return "MESH_ERR_IO";
        case MESH_ERR_UNIMPLEMENTED:  return "MESH_ERR_UNIMPLEMENTED";
        default:                      return "MESH_ERR_?";
    }
}
