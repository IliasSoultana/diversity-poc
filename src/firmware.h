/* firmware.h — shared declarations for the demo firmware */
#pragma once
#include <stdio.h>

int  validate_input(int v);
void handle_error(int code);
void process_sensor(int reading);
void log_event(const char *msg);
void run_pipeline(int input);
void calibrate(void);
void shutdown_sequence(void);
