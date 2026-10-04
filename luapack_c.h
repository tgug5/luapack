/*
 * luapack_c.h  —  luapack 加密容器的 C 运行时解密库
 *
 * 用途：宿主程序（C/C++ 游戏引擎、Android JNI、嵌入式）在加载 Lua 之前
 *       把 .luac.enc 解回字节码，再喂给 luaL_loadbuffer。
 *
 * 自包含，零第三方依赖：
 *   SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256 / AES-256-CBC / XXTEA-128
 *
 * 用法：
 *     lpk_buffer bc;
 *     if (lpk_decrypt_file("demo.luac.enc", "your-password", &bc) == 0) {
 *         luaL_loadbuffer(L, (const char *)bc.data, bc.len, "@demo");
 *         lua_pcall(L, 0, LUA_MULTRET, 0);
 *         lpk_free(&bc);
 *     }
 *
 * 返回码：
 *     0  成功
 *   -1  参数错误
 *   -2  文件/内存读取失败
 *   -3  不是 luapack 容器
 *   -4  容器版本不支持
 *   -5  口令错误
 *   -6  完整性校验失败（HMAC / CRC32）
 *   -7  数据损坏或长度异常
 *   -8  该加密算法本库未启用
 */
#ifndef LUAPACK_C_H
#define LUAPACK_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LPK_HEADER_SIZE 128

typedef struct {
    uint8_t *data;
    size_t   len;
} lpk_buffer;

typedef struct {
    int    lua_ver;      /* 5、6 -> 5.1 / 5.2 / 5.3 / 5.4 对应 51/52/53/54 */
    int    cipher;       /* 0=xxtea 1=aes 2=none */
    int    scramble;
    int    hmac;
    int    strong_kdf;
    size_t bytecode_len;
    size_t payload_len;
    uint64_t packed_at;
} lpk_info_t;

/* 内存里的容器 → 字节码。成功返回 0，out->data 需 lpk_free 释放 */
int  lpk_decrypt(const uint8_t *blob, size_t blob_len,
                 const char *password, lpk_buffer *out);

/* 文件版 */
int  lpk_decrypt_file(const char *path, const char *password, lpk_buffer *out);

/* 只看头部信息，不需要口令 */
int  lpk_peek(const uint8_t *blob, size_t blob_len, lpk_info_t *info);
int  lpk_peek_file(const char *path, lpk_info_t *info);

void lpk_free(lpk_buffer *buf);

const char *lpk_strerror(int code);

#ifdef __cplusplus
}
#endif
#endif /* LUAPACK_C_H */
