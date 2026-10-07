/* FlySafe CIVL G-record validator. The executable contains public key material only.
 * Plain Ed25519(SHA256(protected original IGC bytes)), not Ed25519ph.
 * CIVL 7H 3.1.4.2: HO headers and L records from other manufacturers are unprotected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>
#include "public_key.h"

static int reject(FILE *file, const char *reason)
{
    if (file) fclose(file);
    fprintf(stderr, "INVALID: %s\n", reason);
    return 1;
}

static int digits(const char *text, size_t length)
{
    size_t i;
    int value = 0;
    for (i = 0; i < length; i++) {
        if (text[i] < '0' || text[i] > '9') return -1;
        value = value * 10 + text[i] - '0';
    }
    return value;
}

static int altitude(const char *text)
{
    return text[0] == '-' ? digits(text + 1, 4) >= 0 : digits(text, 5) >= 0;
}

static int valid_fix(const char *line, size_t length)
{
    int hour, minute, second, lat, lat_min, lon, lon_min;
    if (length < 35) return 0;
    hour = digits(line + 1, 2);
    minute = digits(line + 3, 2);
    second = digits(line + 5, 2);
    lat = digits(line + 7, 2);
    lat_min = digits(line + 9, 5);
    lon = digits(line + 15, 3);
    lon_min = digits(line + 18, 5);
    return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59
        && second >= 0 && second <= 60 && lat >= 0 && lat <= 90
        && lat_min >= 0 && lat_min < 60000 && (lat != 90 || lat_min == 0)
        && lon >= 0 && lon <= 180 && lon_min >= 0 && lon_min < 60000
        && (lon != 180 || lon_min == 0) && (line[14] == 'N' || line[14] == 'S')
        && (line[23] == 'E' || line[23] == 'W') && (line[24] == 'A' || line[24] == 'V')
        && altitude(line + 25) && altitude(line + 30);
}

static int valid_date(const char *text)
{
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int day = digits(text, 2), month = digits(text + 2, 2), year = digits(text + 4, 2);
    int max_day;
    if (month < 1 || month > 12 || year < 0) return 0;
    max_day = days[month - 1] + (month == 2 && year % 4 == 0);
    return day >= 1 && day <= max_day;
}

static int64_t date_day(const char *text)
{
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int day = digits(text, 2), month = digits(text + 2, 2), year = digits(text + 4, 2), i;
    int64_t result = 0;
    for (i = 0; i < year; i++) result += 365 + (i % 4 == 0);
    for (i = 1; i < month; i++) result += days[i - 1] + (i == 2 && year % 4 == 0);
    return result + day - 1;
}

/* Required flight-recorder headers, including the CIVL altitude declarations. */
static const char *required_headers[] = {
    "PLT", "CM2", "GTY", "GID", "DTM", "RFW", "RHW", "FTY", "GPS", "PRS", "ALG", "ALP"
};
#define REQUIRED_HEADERS ((1u << (sizeof(required_headers) / sizeof(required_headers[0]))) - 1u)

static int unprotected(const char *line, size_t length)
{
    if (length >= 2 && line[0] == 'H' && line[1] == 'O') return 1;
    return length >= 4 && line[0] == 'L' && memcmp(line + 1, "XFS", 3) != 0;
}

static int validate(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    crypto_hash_sha256_state state;
    unsigned char digest[crypto_hash_sha256_BYTES], signature[crypto_sign_BYTES];
    char line[1024], signature_hex[129] = {0};
    size_t length, i, signature_length;
    unsigned long line_number = 0, fixes = 0;
    unsigned headers = 0;
    int g_records = 0, scheme = 0, dates = 0, ch, fxa = 0;
    int64_t day = -1, last_fix = -1;
    if (!file) return reject(NULL, "cannot open IGC file");
    crypto_hash_sha256_init(&state);
    /* Read bytes explicitly so embedded NULs and unterminated lines cannot hide data. */
    for (;;) {
        length = 0;
        while ((ch = fgetc(file)) != EOF) {
            if (length >= sizeof(line) - 1) return reject(file, "IGC record too long");
            line[length++] = (char) ch;
            if (ch == '\n') break;
        }
        if (length == 0) break;
        line_number++;
        if (length < 3 || line[length - 2] != '\r' || line[length - 1] != '\n')
            return reject(file, "original CRLF records required");
        for (i = 0; i < length - 2; i++) {
            if ((unsigned char) line[i] < 32 || (unsigned char) line[i] > 126)
                return reject(file, "IGC contains non-ASCII or control bytes");
        }
        line[length] = '\0';
        if (line_number == 1 && (length < 6 || memcmp(line, "AXFS", 4) != 0))
            return reject(file, "first record must begin with AXFS");
        if (line_number > 1 && line[0] == 'A') return reject(file, "multiple recorder identities");
        if (line[0] == 'G') {
            if (length != 67 || g_records >= 2) return reject(file, "require two 64-hex G records");
            memcpy(signature_hex + g_records * 64, line + 1, 64);
            g_records++;
            continue;
        }
        if (unprotected(line, length - 2)) continue;
        if (g_records) return reject(file, "protected record appended after signature");
        if (!strchr("ABCEFHIJKL", line[0]))
            return reject(file, "unknown IGC record type");
        if (line[0] == 'B') {
            int64_t timestamp;
            if (!dates || headers != REQUIRED_HEADERS || !valid_fix(line, length - 2))
                return reject(file, "invalid B record or missing required headers");
            if (length - 2 != (size_t)(fxa ? 38 : 35) || (fxa && digits(line + 35, 3) < 0))
                return reject(file, "B record extensions do not match the I record");
            if (line[24] == 'V' && memcmp(line + 30, "00000", 5) != 0)
                return reject(file, "invalid fix must have zero GNSS altitude");
            timestamp = day * 86400 + digits(line + 1, 2) * 3600
                + digits(line + 3, 2) * 60 + digits(line + 5, 2);
            if (timestamp <= last_fix) return reject(file, "fix UTC times must increase");
            last_fix = timestamp;
            fixes++;
        }
        if (strncmp(line, "HFDTE", 5) == 0) {
            const char *value = line + 5;
            if (strncmp(value, "DATE:", 5) == 0) value += 5;
            if ((size_t)(line + length - 2 - value) < 6 || !valid_date(value))
                return reject(file, "invalid flight date");
            day = date_day(value);
            dates++;
        }
        if (length >= 8 && line[0] == 'H' && line[1] == 'F') {
            for (i = 0; i < sizeof(required_headers) / sizeof(required_headers[0]); i++) {
                if (memcmp(line + 2, required_headers[i], 3) == 0) {
                    const char *colon = strchr(line + 5, ':');
                    unsigned bit = 1u << i;
                    if (fixes || (headers & bit) || !colon || colon + 1 >= line + length - 2)
                        return reject(file, "missing, repeated or late recorder header value");
                    if (strcmp(required_headers[i], "DTM") == 0 && strcmp(colon + 1, "WGS84\r\n") != 0)
                        return reject(file, "GPS datum must be WGS84");
                    if (strcmp(required_headers[i], "ALG") == 0 && strcmp(colon + 1, "GEO\r\n") != 0)
                        return reject(file, "GNSS altitude must reference the geoid");
                    if (strcmp(required_headers[i], "ALP") == 0 && strcmp(colon + 1, "ISA\r\n") != 0
                        && strcmp(colon + 1, "NIL\r\n") != 0)
                        return reject(file, "pressure altitude must be ISA or unavailable");
                    headers |= bit;
                    break;
                }
            }
        }
        if (line[0] == 'I') {
            if (fixes || fxa || strcmp(line, "I013638FXA\r\n") != 0)
                return reject(file, "unsupported or late I record");
            fxa = 1;
        }
        if (strcmp(line, "LXFSFLYSAFE ED25519-SHA256-V1\r\n") == 0) scheme++;
        if (strncmp(line, "LXFSFLYSAFE RESET RECOVERY", 25) == 0
            || (strncmp(line, "LXFSFLYSAFE", 11) == 0 && strstr(line, "UNSIGNED") != NULL)) return reject(file, "recording is explicitly unsigned");
        /* Legacy key declarations stay in the signed bytes, but never select a verification key. */
        crypto_hash_sha256_update(&state, (const unsigned char *) line, (unsigned long long) length);
    }
    if (ferror(file)) return reject(file, "read error");
    fclose(file);
    if (g_records != 2 || scheme != 1 || !dates || !fixes || headers != REQUIRED_HEADERS)
        return reject(NULL, "missing signature, scheme, required headers, date or fixes");
    if (sodium_hex2bin(signature, sizeof(signature), signature_hex, 128, NULL,
                       &signature_length, NULL) != 0 || signature_length != sizeof(signature))
        return reject(NULL, "invalid signature hex");
    crypto_hash_sha256_final(&state, digest);
    if (crypto_sign_verify_detached(signature, digest, sizeof(digest), flysafe_public_key) != 0)
        return reject(NULL, "G-record signature does not match recorded data");
    printf("VALID: FlySafe G-record verified (%lu fixes)\n", fixes);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        fprintf(argc == 2 ? stdout : stderr,
                "FlySafe CIVL G-record validator\nUsage: %s flight.igc\n"
                "Exit codes: 0 valid, 1 invalid, 2 usage/error.\n", argv[0]);
        return argc == 2 ? 0 : 2;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: cryptographic library initialization failed\n");
        return 2;
    }
    return validate(argv[1]);
}
