#include "firmware.h"
int main(void) {
    calibrate();
    run_pipeline(800);
    run_pipeline(-1);
    shutdown_sequence();
    return 0;
}
