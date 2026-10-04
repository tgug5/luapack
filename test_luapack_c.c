/*
 * test_luapack_c.c  —  C 库自测 / 与 luapack.py 产物对拍
 *
 * 编译:  gcc -O2 -o lpk_test test_luapack_c.c luapack_c.c
 * 用法:  ./lpk_test <enc-file> <password> [out.bin]
 *        ./lpk_test peek <enc-file>
 */
#include "luapack_c.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "peek") == 0) {
        lpk_info_t info;
        int rc = lpk_peek_file(argv[2], &info);
        if (rc != 0) {
            printf("PEEK_FAIL %d %s\n", rc, lpk_strerror(rc));
            return 1;
        }
        printf("PEEK_OK lua=5.%d cipher=%d scramble=%d hmac=%d strong_kdf=%d bc=%zu payload=%zu\n",
               info.lua_ver, info.cipher, info.scramble, info.hmac,
               info.strong_kdf, info.bytecode_len, info.payload_len);
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: %s <enc-file> <password> [out.bin]\n", argv[0]);
        fprintf(stderr, "       %s peek <enc-file>\n", argv[0]);
        return 2;
    }

    {
        lpk_buffer bc;
        int rc = lpk_decrypt_file(argv[1], argv[2], &bc);
        if (rc != 0) {
            printf("DECRYPT_FAIL %d %s\n", rc, lpk_strerror(rc));
            return 1;
        }
        printf("DECRYPT_OK len=%zu head=", bc.len);
        {
            size_t i;
            for (i = 0; i < 8 && i < bc.len; i++) printf("%02x", bc.data[i]);
        }
        printf("\n");
        if (argc >= 4) {
            FILE *f = fopen(argv[3], "wb");
            if (!f) { printf("WRITE_FAIL\n"); lpk_free(&bc); return 1; }
            fwrite(bc.data, 1, bc.len, f);
            fclose(f);
            printf("WROTE %s\n", argv[3]);
        }
        lpk_free(&bc);
    }

    /* 错口令必须被拒 */
    {
        lpk_buffer bc;
        int rc = lpk_decrypt_file(argv[1], "definitely-wrong-password", &bc);
        printf(rc != 0 ? "WRONGPW_REJECTED ok\n" : "WRONGPW_REJECTED FAIL(should reject)\n");
        if (rc == 0) lpk_free(&bc);
    }
    return 0;
}
