#ifndef TOOLS_H
#define TOOLS_H

#include <stdint.h>
#include <stdio.h>

static inline void
_dump_state(const char *msg,
            const uint32_t *state)
{
        fprintf(stderr, "%s\n", msg);
        for (unsigned i = 0; i < 16; i += 4) {
                fprintf(stderr, "0x%08x 0x%08x 0x%08x 0x%08x\n",
                        state[i + 0],
                        state[i + 1],
                        state[i + 2],
                        state[i + 3]);
        }
}

static inline void
_hexdump(const char *msg,
         const void *p,
         size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        fprintf(stderr, "%s\n", msg);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for(; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for(i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];

                        if ( (c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out, sizeof(line) - out, "%c", c);
                }
                fprintf(stderr, "%s\n", line);
        }
}

#if defined(DEBUG)
# define HEXDUMP(m,p,l)	_hexdump(m,p,l)
# define DUMP_STATE(m,x) _dump_state(m,x)
#else
# define HEXDUMP(m,p,l)
# define DUMP_STATE(m,x)
#endif

#endif /* TOOLS_H */
