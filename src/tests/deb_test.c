#include <stddef.h>

#include "config.h"
#include "conf.h"
#include "backend-manager.h"
#include "message.h"

int main(int argc, char * const argv[]) {
    set_message_mode(MSG_STDERR, DBG_YES);

    conf_t conf;
    conf.trust = "debdb";
    backend_init(&conf);
    backend_load(&conf);
    backend_entry* debdb_entry = backend_get_first();
    backend *debdb = NULL;
    if (debdb_entry != NULL) {
        debdb = debdb_entry->backend;
    } else {
        msg(LOG_ERR, "ERROR: No backends registered.");
    }
    if (debdb == NULL) {
        msg(LOG_ERR, "ERROR: debdb not registered");
    }

    backend_close();

    return 0;
}