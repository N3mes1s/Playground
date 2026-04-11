#ifndef NTUM_SIGNALS_H
#define NTUM_SIGNALS_H

/* Install NTUM signal handler for page fault handling */
void ntum_signal_init(void);

/* Set PE raw data source for demand-paging with real content */
void ntum_signal_set_pe_data(void *raw_data, size_t raw_size, uint64_t image_base);

#endif
