#include "firmware.h"
void process_sensor(int reading) {
    if (!validate_input(reading)) { handle_error(reading); return; }
    printf("sensor: %d\n", reading);
}
