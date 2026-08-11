#include "firmware.h"
void run_pipeline(int input) {
    if (!validate_input(input)) { handle_error(input); return; }
    process_sensor(input);
    log_event("ok");
}
