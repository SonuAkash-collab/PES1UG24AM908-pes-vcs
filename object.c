// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Build the header string
    const char *type_str;
    if (type == OBJ_BLOB) {
        type_str = "blob";
    } else if (type == OBJ_TREE) {
        type_str = "tree";
    } else if (type == OBJ_COMMIT) {
        type_str = "commit";
    } else {
        return -1;
    }

    // Build header: "<type> <size>\0"
    char header_buf[64];
    int hdr_len = snprintf(header_buf, sizeof(header_buf), "%s %zu", type_str, len);
    if (hdr_len < 0 || hdr_len >= (int)sizeof(header_buf)) {
        return -1;
    }
    hdr_len++; // Include the null byte in the header

    // Step 2: Concatenate header + data into one buffer
    size_t full_len = hdr_len + len;
    void *full_obj = malloc(full_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header_buf, hdr_len);
    memcpy((char *)full_obj + hdr_len, data, len);

    // Step 3: Compute SHA-256 hash of the full object
    compute_hash(full_obj, full_len, id_out);

    // Step 4: Check for deduplication (object already exists)
    if (object_exists(id_out)) {
        free(full_obj);
        return 0; // Already stored, nothing to do
    }

    // Step 5: Create shard directory if needed
    char shard_dir[256];
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);

    if (mkdir(shard_dir, 0755) < 0) {
        // EEXIST is fine (directory already exists)
        if (errno != EEXIST) {
            free(full_obj);
            return -1;
        }
    }

    // Step 6: Write atomically to a temp file, then rename
    char temp_path[512], final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", final_path);

    // Write full object to temp file
    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_obj);
        return -1;
    }

    ssize_t written = write(fd, full_obj, full_len);
    if (written < 0 || (size_t)written != full_len) {
        close(fd);
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    // Step 7: fsync to ensure data hits disk
    if (fsync(fd) < 0) {
        close(fd);
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    if (close(fd) < 0) {
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    // Step 8: Atomic rename
    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    // Step 9: fsync the shard directory to persist the rename
    fd = open(shard_dir, O_RDONLY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }

    free(full_obj);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Build the file path from the hash
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1; // File not found or can't open
    }

    // Determine file size
    if (fseek(f, 0, SEEK_END) < 0) {
        fclose(f);
        return -1;
    }
    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);

    // Read entire file into buffer
    void *file_data = malloc(file_size);
    if (!file_data) {
        fclose(f);
        return -1;
    }

    if (fread(file_data, 1, file_size, f) != (size_t)file_size) {
        free(file_data);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Step 3: Parse header to extract type and size
    // Header format: "<type> <size>\0<data>"
    void *null_pos = memchr(file_data, '\0', file_size);
    if (!null_pos) {
        free(file_data);
        return -1; // No null byte separator found
    }

    size_t header_len = (char *)null_pos - (char *)file_data;
    char *header = (char *)file_data;

    // Parse type string from header
    const char *type_str = NULL;
    ObjectType type_val;
    if (strncmp(header, "blob", 4) == 0 && (header[4] == ' ' || header[4] == '\0')) {
        type_str = "blob";
        type_val = OBJ_BLOB;
    } else if (strncmp(header, "tree", 4) == 0 && (header[4] == ' ' || header[4] == '\0')) {
        type_str = "tree";
        type_val = OBJ_TREE;
    } else if (strncmp(header, "commit", 6) == 0 && (header[6] == ' ' || header[6] == '\0')) {
        type_str = "commit";
        type_val = OBJ_COMMIT;
    } else {
        free(file_data);
        return -1; // Invalid type
    }

    // Parse size from header
    size_t expected_size = 0;
    if (sscanf(header, "%*s %zu", &expected_size) != 1) {
        free(file_data);
        return -1;
    }

    // Calculate actual data portion
    size_t data_offset = header_len + 1; // Skip null byte
    size_t actual_data_len = file_size - data_offset;

    if (actual_data_len != expected_size) {
        free(file_data);
        return -1; // Size mismatch
    }

    // Step 4: Verify integrity by recomputing hash
    ObjectID recomputed_hash;
    compute_hash(file_data, file_size, &recomputed_hash);

    if (memcmp(recomputed_hash.hash, id->hash, HASH_SIZE) != 0) {
        free(file_data);
        return -1; // Hash mismatch — corrupted object
    }

    // Step 5: Set output parameters
    *type_out = type_val;
    *data_out = malloc(actual_data_len);
    if (!*data_out) {
        free(file_data);
        return -1;
    }
    memcpy(*data_out, (char *)file_data + data_offset, actual_data_len);
    *len_out = actual_data_len;

    free(file_data);
    return 0;
}
