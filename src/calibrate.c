#include "firmware.h"
void calibrate(void) { log_event("calibrating"); process_sensor(512); }
