#include <dpkg/pkg-array.h>
#include <dpkg/fsys.h>
#include <dpkg/db-fsys.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uthash.h>
#include <fcntl.h>


#include "message.h"
#include "conf.h"
#include "fapolicyd-backend.h"
#include "llist.h"

const int kSha256BytesLength = 32;
const int kSha256HexLength = 64;
const int kMd5BytesLength = 16;
const int kMd5HexLength = 32;
const int kMaxKeyLength = 4096;

static int deb_init_backend(void);
static int deb_load_list(const conf_t *);
static int deb_destroy_backend(void);

backend deb_backend =
{
	"debdb",
	deb_init_backend,
	deb_load_list,
	deb_destroy_backend,
	/* list initialization */
	{ 0, 0, NULL },
};

struct _hash_record {
	const char * key;
	UT_hash_handle hh;
};

/*
 * Given a path to a file with an expected MD5 digest, add
 * the file to the trust database if it matches.
 * 
 * Dpkg does not provide sha256 sums or file sizes to verify against.
 * The only source for verification is MD5. The logic implemented is:
 * 1) Calculate the MD5 sum and compare to the dpkg database. If it does
 *    not match, abort.
 * 2) Calculate the SHA256 and file size on the local files.
 * 3) Add to database.
 * 
 * Security considerations:
 * An attacker would need to craft a file with a MD5 hash collision.
 * While MD5 is considered broken, this is still some effort.
 * This function would compute a sha256 and file size on the attackers
 * crafted file so they do not secure this backend.
*/
static int add_file_to_backend(
    const char* path, struct _hash_record *hashtable, const char* expected_md5) {
    struct stat path_stat;
    stat(path, &path_stat);

    // If its not a regular file, skip.
    if (!S_ISREG(path_stat.st_mode)) {
        return 1;
    }
    
    // Open the file and calculate sha256 and size.
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        msg(LOG_WARNING, "Could not open %s", path);
        return 1;
    }
    size_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char* sha_digest = get_hash_from_fd2(fd, file_size);
    lseek(fd, 0, SEEK_SET);
    char* md5_digest = get_hash_from_fd2(fd, file_size, false);
    close(fd);    

    if (strcmp(md5_digest, expected_md5) != 0) {
        msg(LOG_WARNING,
            "Skipping %s as hash mismatched. Should be %s, got %s",
            path, expected_md5, md5_digest);
        free(sha_digest);
        free(md5_digest);
        return 1;
    }
    free(md5_digest);

    char *data;
    if (asprintf(&data,
            DATA_FORMAT,
            path,
            file_size,
            sha_digest) == -1) {
        data = NULL;
    }
    free(sha_digest);

    if (data) {
        // Getting rid of the duplicates.
        struct _hash_record *rcd = NULL;
        char key[kMaxKeyLength];
        snprintf(key, kMaxKeyLength - 1, "%s %s", path, data);

        HASH_FIND_STR(hashtable, key, rcd );

        if (!rcd) {
            rcd = (struct _hash_record*) malloc(sizeof(struct _hash_record));
            rcd->key = strdup(key);
            HASH_ADD_KEYPTR(hh, hashtable, rcd->key, strlen(rcd->key), rcd);
            list_append(&deb_backend.list, path, data);
        } else {
            free((void*)data);
        }
        msg(LOG_DEBUG, "Added %s to database.", path);
        return 0;
    }
    return 1;
}

static int deb_load_list(const conf_t *conf) {
    
    list_empty(&deb_backend.list);
    struct _hash_record *hashtable = NULL;
    
    msg(LOG_INFO, "Loading debdb backend");
    
    enum modstatdb_rw status = msdbrw_readonly;

    status = modstatdb_open(msdbrw_readonly);
    if (status != msdbrw_readonly) {
        msg(LOG_ERR, "Could not open database for reading. Status %d", status);
        return 1;
    }
    // Load filenames for package.
    ensure_allinstfiles_available();
    ensure_diversions();

    struct pkg_array array;
    pkg_array_init_from_hash(&array);

    msg(LOG_INFO, "Adding %d packages.", array.n_pkgs);

    for (int i = 0; i < array.n_pkgs; i++) {
        struct pkginfo *package = array.pkgs[i];
        if (package->status != PKG_STAT_INSTALLED) {
            continue;
        }
        struct fsys_namenode_list *file = package->files;
        if (!file) {
            // Package does not have any files.
            continue;
        }
        // Loop over all files in the package, adding them to debdb.
        int count = 0;
        while (file) {
            count += 1;
            struct fsys_namenode *namenode = file->namenode;
            // Get the hash and path of the file.
            const char *hash = (namenode->newhash == NULL) ? namenode->oldhash : namenode->newhash;
            const char *path = (namenode->divert && !namenode->divert->camefrom) ?
                namenode->divert->useinstead->name : namenode->name;
            if (hash != NULL) {
                add_file_to_backend(path, hashtable, hash);
            }
            file = file->next;
        }
    }
    
    pkg_array_destroy(&array);
    modstatdb_shutdown();
    return 0;
}

static int deb_init_backend() {
    dpkg_program_init("debdb");
    list_init(&deb_backend.list);
    return 0;
}

static int deb_destroy_backend() {
    dpkg_program_done();
    list_empty(&deb_backend.list);
	return 0;
}
