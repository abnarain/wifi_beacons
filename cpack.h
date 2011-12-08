#ifndef _CPACK_HEADER_H_
#define _CPACK_HEADER_H_
u_int8_t * cpack_next_boundary(u_int8_t *buf, u_int8_t *p, size_t alignment);
u_int8_t * cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize);
int cpack_uint32(struct cpack_state *cs, u_int32_t *u) ;
int cpack_uint16(struct cpack_state *cs, u_int16_t *u) ;
int cpack_uint8(struct cpack_state *cs, u_int8_t *u);
int cpack_init(struct cpack_state *cs, u_int8_t *buf, size_t buflen);
int cpack_uint64(struct cpack_state *cs, u_int64_t *u);
#endif