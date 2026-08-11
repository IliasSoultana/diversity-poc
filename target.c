/*
 * target.c — demo firmware-style program used to show build diversity.
 *
 * Contains several named functions so that function-reordering between builds
 * is clearly visible when comparing symbol addresses.
 */
#include <stdio.h>

int validate_input(int v) {
    return v >= 0 && v <= 1023;
}

void handle_error(int code) {
    printf("error: %d\n", code);
}

void process_sensor(int reading) {
    if (!validate_input(reading)) {
        handle_error(reading);
        return;
    }
    printf("sensor: %d\n", reading);
}

void log_event(const char *msg) {
    printf("[event] %s\n", msg);
}

void run_pipeline(int input) {
    if (!validate_input(input)) {
        handle_error(input);
        return;
    }
    process_sensor(input);
    log_event("ok");
}

void calibrate(void) {
    log_event("calibrating");
    process_sensor(512);
}

void shutdown_sequence(void) {
    log_event("shutdown");
}

int main(void) {
    calibrate();
    run_pipeline(800);
    run_pipeline(-1);
    shutdown_sequence();
    return 0;
}
