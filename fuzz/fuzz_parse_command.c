#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "cmdparse.h"

/*
 * Fuzz parse_command: parses IPC command strings sent from the mtr UI
 * process to the mtr-packet subprocess. The command format is a textual
 * protocol with token, command name, and key-value arguments.
 * Interesting because malformed command strings could cause buffer
 * overflows or other memory safety issues in the argument parser.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) {
        return 0;
    }

    /* Create a null-terminated string from the fuzz input */
    char *command_str = (char *)malloc(size + 1);
    if (!command_str) {
        return 0;
    }
    memcpy(command_str, data, size);
    command_str[size] = '\0';

    /* Initialize the command structure */
    struct command_t command;
    memset(&command, 0, sizeof(command));

    /* Parse the command string */
    int result = parse_command(&command, command_str);
    (void)result;

    free(command_str);
    return 0;
}
