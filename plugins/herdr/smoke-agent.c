/* Account-free terminal fixture. Compile as claude and codex for Herdr detection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *binary;
static const char *pane;
static const char *agent;
static char command[4096];

static void state(const char *status) {
    snprintf(command, sizeof command,
        "%s pane report-agent %s --source custom:heartwood-smoke --agent %s --state %s",
        binary, pane, agent, status);
    if (system(command)) exit(1);
}

int main(int argc, char **argv) {
    (void)argc;
    setbuf(stdout, NULL);
    binary = getenv("HERDR_BIN_PATH");
    pane = getenv("HERDR_PANE_ID");
    if (!binary || !pane) return 1;
    agent = strstr(argv[0], "codex") ? "codex" : "claude";
    state("idle");
    printf("STUB READY %s\n", agent);
    char line[16384];
    while (fgets(line, sizeof line, stdin)) {
        if (!strcmp(line, "finish\n")) {
            state("working");
            snprintf(command, sizeof command,
                "%s pane report-metadata %s --source custom:heartwood-smoke "
                "--title 'Added parser; review edge cases next'", binary, pane);
            if (system(command)) return 1;
            state("idle");
            printf("FINISHED %s\n", agent);
        } else printf("RECEIVED %s", line);
    }
    return 0;
}
