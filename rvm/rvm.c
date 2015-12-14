/* rvm.c
 *
 * An implementation of recoverable virtual memory
 * Class: OMS CS 6210
 * Assignment: Project 4
 * Student: Michael Winstead
 * Due Date: 20150419
 */

//Needed for mmap options
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rvm.h"
#include "seqsrchst.h"
#include "steque.h"

#define PATH_NAME_MAX_LENGTH 127           //     Maximum file name to prevent
                                           // overflows
#define REDO_LOG_FILE_NAME "rvm_redo_log"  // Default redo log filename
#define ON_DISK_ENTRY_OFFSET 12            //     Pre-computed offset from the
                                           // beginning of the file to segment
                                           // entries

//Let us be sensitive to the OS upon which we will be running
#ifdef _WIN32
    #define PATH_DIRECTORY_CHARACTER '\\'
#else
    #define PATH_DIRECTORY_CHARACTER '/'
#endif

#define E_SUCCESS 0             // Why isn't this a thing?!
#define TRUE ((uint8_t) (~0))   // readability
#define FALSE ((uint8_t) 0)     // readability

/*
 * AMAZING hexdump function for when you don't want to fire up a debugger
 * modified to use stderr after borrowed from this StackOverflow question:
 *     http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-
 *         structure-data
 * Credit: paxdiablo
 */
void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        fprintf(stderr, "%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf(stderr, "  %s\n", buff);

            // Output the offset.
            fprintf(stderr, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf(stderr, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf(stderr, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf(stderr, "  %s\n", buff);
}

/* _rvm_print_redo_log
 *
 * Debugging function to output a redo log
 *
 * @param redo_t redo_log: the redo log to be printed to stderr
 */
void _rvm_print_redo_log(redo_t redo_log)
{
    segentry_t* current_entry = NULL;
    int current_entry_idx = 0;
    int current_update_index = 0;
    fprintf(stderr, "Printout of redo_log size %d\n", redo_log->numentries);
    while(current_entry_idx < redo_log->numentries)
    {
        current_entry = &redo_log->entries[current_entry_idx];
        fprintf(stderr, "\tEntry %s has %d updates totaling %d\n",
                current_entry->segname, current_entry->numupdates,
                current_entry->updatesize);
        current_update_index = 0;
        while(current_update_index < current_entry->numupdates)
        {
            fprintf(stderr, "\t\tUpdate %d@+%d\n",
                    current_entry->sizes[current_update_index],
                    current_entry->offsets[current_update_index]
                    );
            current_update_index += 1;
        }
        current_entry_idx += 1;
    }
}
/* _rvm_offset_to_pointer
 *
 * Convenience function to convert an offset to a pointer given a base address
 *
 * @param void* base: the base address from which to calculate the offset
 * @param size_t offset: how far from the base address to calculate
 * @returns void* the offset converted to a pointer
 */
__inline__ void* _rvm_offset_to_pointer(void* base, size_t offset)
{
    return (void*) ((size_t)base + (size_t)offset);
}
/* _rvm_pointer_to_offset
 *
 * Convenience function to convert a pointer to an offset from a base address
 *
 * @param void* base: the base address from which to canculate the pointer
 * @param void* pointer: the pointer which will become an offset
 * @returns void* the pointer converted to an offset
 */
__inline__ void* _rvm_pointer_to_offset(void* base, void* pointer)
{
    return (void*) ((size_t)pointer - (size_t)base);
}
/* _rvm_seqsearch_key_compare
 *
 *     Function provided to sequential search structure to compare whether keys
 * are equal
 *
 * @param seqsrchst_key a: The first key to compare
 * @param seqsrchst_key b: The second key to compare
 * @returns zero if keys aren't equal, non-zero otherwise
 */
int _rvm_seqsearch_key_compare(seqsrchst_key a, seqsrchst_key b)
{
    return a == b;
}
/* _rvm_get_segment_by_name
 *
 *     Function to query active segments by segment name rather than by base
 * address.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param char* desired_name: the segment name which is desired
 * @returns segment_t corresponding to provided name
 */
segment_t _rvm_get_segment_by_name(rvm_t rvm, char* desired_name)
{
    int current_segment_index = 0;
    seqsrchst_node* current_node = NULL;
    segment_t candidate = NULL;
    if(seqsrchst_size(&rvm->segst) > 0)
    {
        current_node = rvm->segst.first;
        candidate = current_node->value;
        for(current_segment_index = 0;
                current_segment_index < seqsrchst_size(&rvm->segst);
                current_segment_index += 1)
        {
            if(strcmp(desired_name, candidate->segname) == 0)
            {
                break;
            }
            if(current_segment_index < seqsrchst_size(&rvm->segst))
            {
                current_node = current_node->next;
                candidate = current_node->value;
            }
        }
    }
    return candidate;
}

/* _rvm_get_full_file_name
 *
 *     Converts a file name to a relative one according to the segment
 * directory which the rvm context is currently managing.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param char* file_name: the file name calculated relative to the rvm
 * @returns char* full file name which the caller is responsible for freeing
 */
char* _rvm_get_full_file_name(rvm_t rvm, char* file_name)
{
    size_t rvm_prefix_length = strlen(rvm->prefix);
    size_t file_name_length = strlen(file_name);

    char* to_be_returned = calloc(rvm_prefix_length + file_name_length + 1,
                                  sizeof(char));

    strcpy(to_be_returned, (const char*) rvm->prefix);
    to_be_returned[strlen(to_be_returned)] = PATH_DIRECTORY_CHARACTER;
    strcat(to_be_returned, file_name);
    return to_be_returned;
}
/* _rvm_get_file_size
 *
 *     Conveniece function which stats the provided file descriptor and returns
 * its size
 *
 * @param int fd: file descriptor to query
 * @returns size_t the file's size which the file descriptor describes
 */
size_t _rvm_get_file_size(int fd)
{
    struct stat stat_struct;
    if(fstat(fd, &stat_struct) == 0)
    {
    }else
    {
        fprintf(stderr, "Could not stat: %s\n", strerror(errno));
        exit(1);
    }
    return stat_struct.st_size;
}
/* _rvm_add_segment_to_transaction
 *
 * Function which adds a segment to a transaction
 *
 * @param segment_t segment: the segment which will be added to the supplied
 *     transaction
 * @param trans_t transaction: the transaction which will contain the supplied
 *     segment
 */
void _rvm_add_segment_to_transaction(segment_t segment, trans_t transaction)
{
    transaction->numsegs += 1;
    transaction->segments = realloc(transaction->segments,
                                    sizeof(segment_t) * transaction->numsegs);
    transaction->segments[transaction->numsegs-1] = segment;
}
/* _rvm_free_transaction
 *
 * Frees the supplied transaction
 *
 * @param trans_t transaction: the transaction to free
 */
void _rvm_free_transaction(trans_t transaction)
{
    if(transaction->numsegs > 0)
    {
        free(transaction->segments);
    }
    free(transaction);
}
/* _rvm_create_new_transaction
 *
 * Allocates a new transaction associated with the provided rvm context
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @returns trans_t of newly created transaction
 */
trans_t _rvm_create_new_transaction(rvm_t rvm)
{
    trans_t to_be_returned = malloc(sizeof(struct _trans_t));

    to_be_returned->segments = calloc(1, sizeof(struct _segment_t));
    to_be_returned->numsegs = 0;
    to_be_returned->rvm = rvm;

    return to_be_returned;
}
/* _rvm_create_backing_store_for_segment
 *
 * Creates a new file backing store for the provided segment
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param segment_t segment: segment for which a backing store should be made
 * @returns file descriptor of correct size for segment
 */
int _rvm_create_backing_store_for_segment(rvm_t rvm, segment_t segment)
{
    char* full_backing_store_path_name = _rvm_get_full_file_name(rvm,
                                                             segment->segname);
    int segment_backing_store_fd = open(full_backing_store_path_name,
                                        O_RDWR | O_CREAT,
                                        S_IRUSR | S_IWUSR);
    free(full_backing_store_path_name);
    if(segment_backing_store_fd == -1)
    {
        fprintf(stderr, "Could not get backing store for '%s': %s\n",
                segment->segname, strerror(errno));
        exit(1);
    }
    if(ftruncate(segment_backing_store_fd, segment->size) != E_SUCCESS)
    {
        fprintf(stderr, "Could not ftruncate file '%s': %s\b",
                segment->segname, strerror(errno));
    }
    /*
    fprintf(stderr, "getting backing store for: '%s' size was %lu now %lu\n",
            segment->segname, old_size,
            _rvm_get_file_size(segment_backing_store_fd));
            */
    return segment_backing_store_fd;
}
/* _rvm_save_segment
 *
 *     Saves the provided segment to an appropriate area on disk according to
 * the provided rvm context
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param segment_t segment: the segment to save to disk
 */
void _rvm_save_segment(rvm_t rvm, segment_t desired_segment)
{
    ssize_t amount_written = 0;
    char* backing_store_file_name = _rvm_get_full_file_name(
            rvm, desired_segment->segname);
    int backing_fd = open(backing_store_file_name, O_RDWR);
    if(backing_fd == -1)
    {
        fprintf(stderr, "Can't open backing file for segment %s for writing: "
                "%s\n", desired_segment->segname, strerror(errno));
        exit(1);
    }else
    {
        amount_written = write(backing_fd, desired_segment->segbase,
                               desired_segment->size);
        if(amount_written > INT_MAX)
        {
            fprintf(stderr, "Instructed to write %d, but wrote %ld: %s\n",
                    desired_segment->size, amount_written, strerror(errno));
            exit(1);
        }else if(amount_written < desired_segment->size)
        {
            fprintf(stderr, "Error while writing to segment %s backing file, "
                    "only wrote %ld: %s\n", desired_segment->segname,
                    amount_written, strerror(errno));
            exit(1);
        }
        /* Debugging
        fprintf(stderr, "Wrote %ld to %s\n", amount_written,
                desired_segment->segname);
                */
    }
    if(close(backing_fd) != 0)
    {
        fprintf(stderr, "Error closing backing file for %s: %s\n",
                desired_segment->segname, strerror(errno));
        exit(1);
    }
    free(backing_store_file_name);
}
/* _rvm_try_load_from_backing_store
 *
 *     Attempts to load the provided segment from disk according to how the
 * provided rvm context is configured. If there is no backing disk, this will
 * not create one.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param sevment_t desired_segment: segment which should be read from disk
 * @return uint8_t non-zero if there was an underlying disk, otherwise zero
 */
uint8_t _rvm_try_load_from_backing_store(rvm_t rvm, segment_t desired_segment)
{
    uint8_t return_value = TRUE;
    ssize_t read_return_value, total_read;
    char* backing_store_file_name = _rvm_get_full_file_name(
        rvm, desired_segment->segname);
    int backing_fd = open(backing_store_file_name, O_RDONLY);

    if(backing_fd == -1 && errno != ENOENT) //Something besides it not being
                                            // present...
    {
        fprintf(stderr, "Error while attempting to open '%s': %s\n",
                backing_store_file_name, strerror(errno));
        exit(1);
    }else if(backing_fd > -1)
    {
        /* Debugging
        fprintf(stderr, "Opening %s has size %lu, should read %d\n",
                backing_store_file_name, _rvm_get_file_size(backing_fd),
                desired_segment->size);
                */
        read_return_value = total_read = 0;
        memset(desired_segment->segbase, 0, desired_segment->size);
        while(read_return_value < desired_segment->size &&
              read_return_value >= 0)
        {
            read_return_value = read(backing_fd,
                                     desired_segment->segbase+total_read,
                                     desired_segment->size);
            total_read += read_return_value;
        }
        if(total_read > INT_MAX)
        {
            fprintf(stderr, "WARNING: reading from '%s' returned more than an "
                    "int can address! Got: %lu\n", backing_store_file_name,
                    total_read);
        }else if(read_return_value == -1)
        {
            fprintf(stderr, "Error while reading from file '%s': %s\n",
                    backing_store_file_name, strerror(errno));
            exit(1);
        }else
        {
            /*
            fprintf(stderr, "Read %lu bytes from '%s', last chunk was %lu\n",
                    total_read, backing_store_file_name, read_return_value);
                    */
        }
        while(close(backing_fd) == -1)
        {
            if(errno != EINTR)
            {
                fprintf(stderr, "Just finished reading a bunch from file "
                        "descriptor %d only to be unable to close it!\n",
                        backing_fd);
                exit(1);
            }
        }
    }else
    {
        return_value = FALSE;
    }
    free(backing_store_file_name);
    return return_value;
}
/* _rvm_save_redo_log
 *
 *     Saves the provided redo log to disk according to how the rvm context is
 * configured
 *
 *  On disk, the redo log is saved in the following format:
 *  -----------------------------------------------
 *  |Data entry| Offset                           |   
 *  -----------------------------------------------
 *  |numentries| 0                                | 
 *  |entries   | 4                                | 
 *  |entry_0   | 12                               | 
 *  |..........|..................................|
 *  |entry_n   |                                  |
 *  |sizes_0   | sizeof(segentry_t) * numentries  |       
 *  |offsets_0 |                                  |
 *  |data_0    |                                  |
 *  |..........|..................................|
 *  |sizes_n   |                                  |
 *  |offsets_n |                                  |
 *  |data_n    |                                  |
 *  -----------------------------------------------
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param redo_t redo_log: the redo log to save to disk
 */
void _rvm_save_redo_log(rvm_t rvm, redo_t redo_log)
{
    int current_entry_idx;
    segentry_t* to_disk_entries = NULL;
    segentry_t* current_to_disk_entry = NULL;
    segentry_t* current_in_memory_entry = NULL;
    ssize_t total_written_to_disk = 0;
    size_t total_size_used_by_pointers = 0;
    size_t total_written_size = sizeof(int) + sizeof(void*);
    void* to_disk = malloc(total_written_size);

    fprintf(stderr, "Save redo log with %d entries, initial size: %lu\n",
            redo_log->numentries, total_written_size);

    //numentries
    memcpy(to_disk, redo_log, sizeof(int));
    //entries
    memcpy(to_disk + sizeof(int), &total_written_size, sizeof(size_t));
    if(redo_log->numentries > 0)
    {
        fprintf(stderr, "Redo log going from %lu to %lu\n", total_written_size,
                total_written_size + (sizeof(segentry_t) *
                    redo_log->numentries));
        total_written_size += sizeof(segentry_t) * redo_log->numentries;

        to_disk = realloc(to_disk, total_written_size);
        to_disk_entries = to_disk + ON_DISK_ENTRY_OFFSET;
        memcpy(to_disk_entries, redo_log->entries,
                sizeof(segentry_t) * redo_log->numentries);

        current_entry_idx = 0;
        current_in_memory_entry = &redo_log->entries[current_entry_idx];
        current_to_disk_entry = &to_disk_entries[current_entry_idx];
        while(current_entry_idx < redo_log->numentries)
        {
            current_to_disk_entry->segsize = current_in_memory_entry->segsize;
            current_to_disk_entry->numupdates =
                current_in_memory_entry->numupdates;
            current_to_disk_entry->updatesize =
                current_in_memory_entry->updatesize;
            strncpy(current_to_disk_entry->segname,
                    current_in_memory_entry->segname, PATH_NAME_MAX_LENGTH);

            total_size_used_by_pointers =
                (2 * sizeof(int) * current_in_memory_entry->numupdates) +
                current_in_memory_entry->updatesize;

            //After realloc-ing, things may have moved, so I have to reassign
            // a number of pointers
            to_disk = realloc(to_disk, total_written_size +
                              total_size_used_by_pointers);
            to_disk_entries = to_disk + ON_DISK_ENTRY_OFFSET;
            current_in_memory_entry = &redo_log->entries[current_entry_idx];
            current_to_disk_entry = &to_disk_entries[current_entry_idx];

            current_to_disk_entry->sizes = (void*) to_disk +
                total_written_size;
            memset(current_to_disk_entry->sizes, 0,
                    sizeof(int) * current_in_memory_entry->numupdates);
            memcpy(current_to_disk_entry->sizes,
                   current_in_memory_entry->sizes,
                   sizeof(int) * current_in_memory_entry->numupdates);
            total_written_size += sizeof(int) *
                                  current_in_memory_entry->numupdates;

            current_to_disk_entry->offsets = (void*) to_disk +
                total_written_size;
            memset(current_to_disk_entry->offsets, 0,
                    sizeof(int) * current_in_memory_entry->numupdates);
            memcpy(current_to_disk_entry->offsets,
                   current_in_memory_entry->offsets,
                   sizeof(int) + current_in_memory_entry->numupdates);
            total_written_size += sizeof(int) *
                                  current_in_memory_entry->numupdates;
            /* Debugging
            hexDump("Source offsets", current_in_memory_entry->offsets,
                    sizeof(int) * current_in_memory_entry->numupdates);
            hexDump("Dest offsets", current_to_disk_entry->offsets,
                    sizeof(int) * current_in_memory_entry->numupdates);
                    */


            current_to_disk_entry->data = (void*) to_disk + total_written_size;
            memset(current_to_disk_entry->data, 0,
                    current_in_memory_entry->updatesize);
            memcpy(current_to_disk_entry->data, current_in_memory_entry->data,
                    current_in_memory_entry->updatesize);
            total_written_size += current_to_disk_entry->updatesize;

            /* Debugging
            fprintf(stderr, "\tSaved %p->%p with %d entries, base @%p, offset "
                    "%lu\n"
                    "\t\tname %s->%s\n"
                    "\t\tsizes: %p->%p %p\n"
                    "\t\toffsets: %p->%p %p\n"
                    "\t\tdata: %p->%p %p\n"
                    "\t\tWrote: %lu\n",
                    current_in_memory_entry,
                    current_to_disk_entry,
                    current_to_disk_entry->numupdates, to_disk,
                    (size_t)_rvm_pointer_to_offset(to_disk,
                        current_to_disk_entry),
                    current_in_memory_entry->segname,
                    current_to_disk_entry->segname,
                    current_in_memory_entry->sizes,
                    current_to_disk_entry->sizes,
                    _rvm_pointer_to_offset(to_disk,
                        current_to_disk_entry->sizes),
                    current_in_memory_entry->offsets,
                    current_to_disk_entry->offsets,
                    _rvm_pointer_to_offset(to_disk,
                        current_to_disk_entry->offsets),
                    current_in_memory_entry->data,
                    current_to_disk_entry->data,
                    _rvm_pointer_to_offset(to_disk,
                        current_to_disk_entry->data),
                    total_written_size);
                    */

            current_to_disk_entry->sizes = _rvm_pointer_to_offset(to_disk,
                                                current_to_disk_entry->sizes);
            current_to_disk_entry->offsets = _rvm_pointer_to_offset(to_disk,
                                            current_to_disk_entry->offsets);
            current_to_disk_entry->data = _rvm_pointer_to_offset(to_disk,
                                            current_to_disk_entry->data);

            current_entry_idx += 1;
            if(current_entry_idx < redo_log->numentries)
            {
                current_in_memory_entry =
                    &redo_log->entries[current_entry_idx];
                current_to_disk_entry = &to_disk_entries[current_entry_idx];
            }
        }
    }
    /* Debugging
    fprintf(stderr, "\tWrote %lu to redo log (%d@%p) %d entries\n",
            total_written_size, rvm->redofd, to_disk, *((int*)to_disk));
            */
    if(ftruncate(rvm->redofd, total_written_size) != 0)
    {
        fprintf(stderr, "Could not change file size in prep for saving: %s\n",
                strerror(errno));
        exit(1);
    }else
    {
        if(lseek(rvm->redofd, 0, SEEK_SET) != 0)
        {
            fprintf(stderr, "Could not seek to beginning of log file: %s\n",
                    strerror(errno));
            exit(1);
        }else
        {
            total_written_to_disk = write(rvm->redofd, to_disk,
                                          total_written_size);
            if(total_written_to_disk < 0)
            {
                fprintf(stderr, "Error when writing redolog back to disk: "
                        "%s\n", strerror(errno));
                exit(1);
            }
            /* Debugging
            fprintf(stderr, "\tFlushed a total of %ld\n",
                    total_written_to_disk);
                    */
        }
    }
}
/* _rvm_get_redo_log
 *
 *     Fetches the serialized redo log which the rvm context is aware of.
 * Caller is responsible for deallocating
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @returns redo_t redo log from the file which the rvm context is aware of
 */
redo_t _rvm_get_redo_log(rvm_t rvm)
{
    int current_update_index, current_entry_index;
    void* from_disk = NULL;
    redo_t unmarshalled_redo_log = NULL;
    segentry_t* from_disk_entries = NULL;
    segentry_t* current_from_disk_sigentry = NULL;
    segentry_t* current_unmarshalled_sigentry = NULL;
    size_t total_segentry_data_size = 0;
    size_t redo_log_file_size = _rvm_get_file_size(rvm->redofd);

    //fprintf(stderr, "Getting redo log size %lu\n", redo_log_file_size);
    from_disk = mmap(NULL,                       //anywhere
                     redo_log_file_size,         //size
                     PROT_READ | PROT_WRITE,     //protection
                     MAP_PRIVATE,                //don't writeback changes
                     rvm->redofd,                //underlying file
                     0);                         //beginning of file
    if((int)from_disk == -1)
    {
        fprintf(stderr, "Could not get redo log: %s\n", strerror(errno));
        exit(1);
    }

    unmarshalled_redo_log = malloc(sizeof(redo_t));
    memcpy(&unmarshalled_redo_log->numentries, from_disk, sizeof(int));

    unmarshalled_redo_log->entries = calloc(unmarshalled_redo_log->numentries,
                                             sizeof(segentry_t));
    /*
    fprintf(stderr, "Got redo log %d@%p\n", unmarshalled_redo_log->numentries,
            from_disk);
            */
    if(unmarshalled_redo_log->entries > 0)
    {
        from_disk_entries = _rvm_offset_to_pointer(from_disk,
                                                   ON_DISK_ENTRY_OFFSET);

        current_update_index = current_entry_index = 0;
        current_from_disk_sigentry =
            &from_disk_entries[current_entry_index];
        current_unmarshalled_sigentry =
            &unmarshalled_redo_log->entries[current_entry_index];

        while(current_entry_index < unmarshalled_redo_log->numentries)
        {
            strncpy(current_unmarshalled_sigentry->segname,
                    current_from_disk_sigentry->segname,
                    PATH_NAME_MAX_LENGTH);
            current_unmarshalled_sigentry->numupdates =
                current_from_disk_sigentry->numupdates;
            current_unmarshalled_sigentry->updatesize =
                current_from_disk_sigentry->updatesize;
            current_unmarshalled_sigentry->segsize =
                current_from_disk_sigentry->segsize;

            /*
            fprintf(stderr, "Pointers are off: %p, size: %p, data: %p\n",
                    current_from_disk_sigentry->offsets,
                    current_from_disk_sigentry->sizes,
                    current_from_disk_sigentry->data);
                    */

            current_from_disk_sigentry->offsets = _rvm_offset_to_pointer(
                    from_disk, (size_t)current_from_disk_sigentry->offsets);
            current_from_disk_sigentry->sizes = _rvm_offset_to_pointer(
                    from_disk, (size_t)current_from_disk_sigentry->sizes);
            current_from_disk_sigentry->data = _rvm_offset_to_pointer(
                    from_disk, (size_t)current_from_disk_sigentry->data);

            /*
            fprintf(stderr, "Pointers are off: %p, size: %p, data: %p\n",
                    current_from_disk_sigentry->offsets,
                    current_from_disk_sigentry->sizes,
                    current_from_disk_sigentry->data);
                    */


            current_unmarshalled_sigentry->offsets =
                calloc(current_unmarshalled_sigentry->numupdates, sizeof(int));

            memcpy(current_unmarshalled_sigentry->offsets,
                   current_from_disk_sigentry->offsets,
                   sizeof(int) * current_unmarshalled_sigentry->numupdates);

            current_unmarshalled_sigentry->sizes =
                calloc(current_unmarshalled_sigentry->numupdates, sizeof(int));
            memcpy(current_unmarshalled_sigentry->sizes,
                   current_from_disk_sigentry->sizes,
                   sizeof(int) * current_unmarshalled_sigentry->numupdates);
            while(current_update_index <
                    current_unmarshalled_sigentry->numupdates)
            {
                total_segentry_data_size +=
                    current_unmarshalled_sigentry->sizes[current_update_index];
                current_update_index += 1;
            }

            current_unmarshalled_sigentry->data =
                malloc(total_segentry_data_size);

            memcpy(current_unmarshalled_sigentry->data,
                   current_from_disk_sigentry->data,
                   total_segentry_data_size);

            current_entry_index += 1;
            if(current_entry_index < unmarshalled_redo_log->numentries)
            {
                current_from_disk_sigentry =
                    &from_disk_entries[current_entry_index];
                current_unmarshalled_sigentry =
                    &unmarshalled_redo_log->entries[current_entry_index];
            }
        }
    }
    munmap(from_disk, redo_log_file_size);
    return unmarshalled_redo_log;
}
/* _rvm_remove_segment_from_redo_log
 *
 * Removes the provided segment from the provided redo log
 *
 * @param redo_t redo_log: the redo log from which the provided segment should
 *      be removed
 * @param segment_t segment: the segment which should be removed from the
 *      provided redo log
 */
void _rvm_remove_segment_from_redo_log(redo_t redo_log, segment_t segment)
{
    int current_entry_index = 0;
    void* next_entry = NULL;
    segentry_t* corresponding_entry = NULL;
    fprintf(stderr, "Removing %s from redo log\n", segment->segname);
    if(redo_log->numentries > 0)
    {
        corresponding_entry = &redo_log->entries[current_entry_index];
        while(current_entry_index < redo_log->numentries)
        {
            if(strcmp(corresponding_entry->segname, segment->segname) == 0)
            {
                //fprintf(stderr, "Found entry @ %d\n", current_entry_index);
                free(corresponding_entry->data);
                free(corresponding_entry->sizes);
                free(corresponding_entry->offsets);
                memset(corresponding_entry, 0, sizeof(segentry_t));
                next_entry = &redo_log->entries[current_entry_index+1];
                memmove(corresponding_entry, next_entry,
                        sizeof(segentry_t) *
                            (redo_log->numentries - current_entry_index));
                redo_log->numentries -= 1;
                current_entry_index -= 1;

                redo_log->entries = realloc(redo_log->entries,
                        sizeof(segentry_t) * redo_log->numentries);
                break;
            } 

            current_entry_index += 1;
            if(current_entry_index < redo_log->numentries)
            {
                corresponding_entry = &redo_log->entries[current_entry_index];
            }
        }
    }
}
/* _rvm_add_segment_to_redo_log
 *
 * Adds the provided segment to the provided redo log
 *
 * @param redo_t redo_log: the redo log to which the provided segment should
 *      be added
 * @param segment_t segment: the segment which should be added to the
 *      provided redo log
 */
void _rvm_add_segment_to_redo_log(redo_t redo_log, segment_t segment)
{
    uint8_t entry_was_in_redo_log = FALSE;
    int current_entry_index = 0;
    int current_update = 0;
    segentry_t* new_entry;
    mod_t* current_modification;
    /* Debugging
    fprintf(stderr, "Adding %s to redo_log %p\n", segment->segname,
            redo_log->entries);
            */
    if(redo_log->numentries > 0)
    {
        new_entry = &redo_log->entries[current_entry_index];
        while(current_entry_index < redo_log->numentries)
        {
            if(strcmp(new_entry->segname, segment->segname) == 0)
            {
                /* Debugging
                fprintf(stderr, "Segment %s was already in redo log had %d "
                        "modifications\n",
                        segment->segname,
                        new_entry->numupdates);
                        */
                entry_was_in_redo_log = TRUE;
                break;
            }
            current_entry_index += 1;
            if(current_entry_index < redo_log->numentries)
            {
                new_entry = &redo_log->entries[current_entry_index];
            }
        }
    }
    if(entry_was_in_redo_log == FALSE)
    {
        redo_log->numentries += 1;
        redo_log->entries = realloc(redo_log->entries,
                                    sizeof(segentry_t) * redo_log->numentries);
        /* Debugging
        fprintf(stderr, "->%p, redo log now contains %d\n", redo_log->entries,
                redo_log->numentries);
                */
        new_entry = &redo_log->entries[redo_log->numentries-1];
        strncpy(new_entry->segname, segment->segname, PATH_NAME_MAX_LENGTH);
        new_entry->updatesize = 0;
        new_entry->sizes = new_entry->offsets = new_entry->data = NULL;
    }
    current_update = new_entry->numupdates;
    new_entry->numupdates += steque_size(&segment->mods);
    new_entry->offsets = realloc(new_entry->offsets,
                                 sizeof(int) * new_entry->numupdates);
    new_entry->sizes = realloc(new_entry->sizes,
                                sizeof(int) * new_entry->numupdates);
    while(steque_size(&segment->mods) > 0)
    {
        current_modification = steque_pop(&segment->mods);
        /* Debugging
        fprintf(stderr, "\tModification #%d %d@%p+%d\n",
                current_update, current_modification->size,
                segment->segbase, current_modification->offset);
        hexDump("new_entry offsets b4", new_entry->offsets,
                sizeof(int) * new_entry->numupdates);
                */
        new_entry->offsets[current_update] = current_modification->offset;
        /* Debugging
        hexDump("new_entry offsets during 1", new_entry->offsets,
                sizeof(int) * new_entry->numupdates);
                */
        new_entry->sizes[current_update] = current_modification->size;

        new_entry->data = realloc(new_entry->data,
                                  new_entry->updatesize +
                                      current_modification->size);
        memcpy(new_entry->data + new_entry->updatesize,
               segment->segbase + current_modification->offset,
               current_modification->size);
        /* Debugging
        hexDump("new_entry offsets during 2", new_entry->offsets,
                sizeof(int) * new_entry->numupdates);
                */

        new_entry->updatesize += current_modification->size;
        /* Debugging
        fprintf(stderr, "\tTotal size: %d\n", new_entry->updatesize);
        */

        free(current_modification->undo);
        free(current_modification);
        current_update += 1;
    }
    /* Debugging
    hexDump("new_entry offsets after", new_entry->offsets,
            sizeof(int) * new_entry->numupdates);
    fprintf(stderr, "Segment %s now has %d modifications totalling %d\n",
            new_entry->segname, new_entry->numupdates,
            new_entry->updatesize);
            */
}
/* _rvm_segment_is_in_redo_log
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param segment_t requested: segment which should be searched for in the
 *     provided redo log
 * @param redo_t* redo_log: redo log which will be searched for this segment.
 *     This also writes back a pointer to a new instantiation of the redo log
 * @param int* index_if_found: if the segment is found, the integer to which
 *     this points will be populated with the provided segment's index within
 *     the redo log's entries array
 * @returns uint8_t zero if segment is not in redo log, non-zero otherwise
 */
uint8_t _rvm_segment_is_in_redo_log(rvm_t rvm, segment_t requested,
                                    redo_t* redo_log, int* index_if_found)
{
    uint8_t is_in_redo_log = FALSE;
    int current_entry;
    *redo_log = _rvm_get_redo_log(rvm);
    for(current_entry = 0; current_entry < (*redo_log)->numentries;
            current_entry++)
    {
        if(strcmp((*redo_log)->entries[current_entry].segname,
                    requested->segname) == 0)
        {
            *index_if_found = current_entry;
            is_in_redo_log = TRUE;
            break;
        }
    }
    return is_in_redo_log;
}
/* _rvm_patch_up_segment_with_redo_log
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param redo_t redo_log: the redo log which will be used to patch up the
 *      provided segment_t
 * @param segment_t new_segment: the segment w3hich will be "fast-forwarded"
 *      using the provided redo log
 * @param int corresponding_index: the index within the redo log's entries
 *      array where the entries which corresponds to the provided segment_t
 *      is positioned
 */
void _rvm_patch_up_segment_with_redo_log(redo_t redo_log,
                                         segment_t new_segment, 
                                         int corresponding_index)
{
    int current_update_idx = 0;
    segentry_t* corresponding_entry = &redo_log->entries[corresponding_index];
    void* current_pointer_into_update_data = corresponding_entry->data;
    /*
    fprintf(stderr, "Patching up segment %s with %d updates totaling %d\n",
            new_segment->segname, corresponding_entry->numupdates,
            corresponding_entry->updatesize);
            */
    for(current_update_idx = 0;
            current_update_idx < corresponding_entry->numupdates;
            current_update_idx += 1)
    {
        /*
        fprintf(stderr, "\tsetting %d@%p+%d(%p)\n",
                corresponding_entry->sizes[current_update_idx],
                new_segment->segbase,
                corresponding_entry->offsets[current_update_idx],
                new_segment->segbase +
                    corresponding_entry->offsets[current_update_idx]);
                    */
        memcpy(new_segment->segbase +
                corresponding_entry->offsets[current_update_idx],
                current_pointer_into_update_data,
                corresponding_entry->sizes[current_update_idx]);

        current_pointer_into_update_data +=
            corresponding_entry->sizes[current_update_idx];
    }
}
/* rvm_init
 *
 * Initialize a new rvm context with the specified directory as backing store.
 *
 * @param const char* directory: directory in which this rvm context should put
 *      the backing stores for its memory segments
 * @returns rvm_t of new recoverable virtual memory context
 */
rvm_t rvm_init(const char *directory)
{
    rvm_t to_be_returned = NULL;
    char* redo_log_file_name = NULL;
    redo_t redo_log = NULL;
    /* Debugging
    fprintf(stderr, "rvm_init: %s\n", directory);
    */
    if(strlen(directory) <= PATH_NAME_MAX_LENGTH)
    {
        if(mkdir(directory, S_IRUSR | S_IWUSR | S_IXUSR) != 0 &&
                errno != EEXIST)
        {
            fprintf(stderr, "Could not create requested directory to store "
                    "segments: %s\n", strerror(errno));
            exit(1);
        }
        to_be_returned = malloc(sizeof(struct _rvm_t));

        strncpy(to_be_returned->prefix, directory, PATH_NAME_MAX_LENGTH);

        redo_log_file_name = _rvm_get_full_file_name(to_be_returned,
                                                     REDO_LOG_FILE_NAME);
        to_be_returned->redofd = open(redo_log_file_name, O_RDWR | O_CREAT,
                                      S_IRUSR | S_IWUSR);
        if(to_be_returned->redofd == -1)
        {
            fprintf(stderr, "Error creating redolog '%s': %s\n",
                    redo_log_file_name, strerror(errno));
            exit(1);
        }else if(_rvm_get_file_size(to_be_returned->redofd) == 0)
        {
            redo_log = malloc(sizeof(struct _redo_t));
            redo_log->numentries = 0;
            redo_log->entries = NULL;
            _rvm_save_redo_log(to_be_returned, redo_log);
            free(redo_log);
        }
        seqsrchst_init(&to_be_returned->segst, &_rvm_seqsearch_key_compare);
    }else
    {
        fprintf(stderr, "Directory name too long for rvm_init: %lu\n",
                strlen(directory));
        exit(1);
    }
    free(redo_log_file_name);
    return to_be_returned;
}
/* rvm_map
 *
 * Map a segment from disk into memory. If the segment does not already exist,
 * then create it and give it size size_to_create. If the segment exists but
 * is shorter than size_to_create, then extend it until it is long enough. It
 * is an error to try to map the same segment twice.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param const char* segname: name of new segment to create
 * @param int size_to_create: the amount of memory to allocate
 * @returns void* of new memory corresponding to the provided segment name
*/
void *rvm_map(rvm_t rvm, const char *segname, int size_to_create)
{
    segment_t new_segment = NULL;
    redo_t redo_log = NULL;
    int segment_entry_redo_log_index = 0;
    void* return_value = 0;
    /* Debugging
    fprintf(stderr, "rvm_map '%s' %d\n", segname, size_to_create);
    */
    if(strlen(segname) <= PATH_NAME_MAX_LENGTH)
    {
        new_segment = calloc(sizeof(struct _segment_t), 1);
        strncpy(new_segment->segname, segname, PATH_NAME_MAX_LENGTH);
        return_value = new_segment->segbase = malloc(size_to_create);
        new_segment->size = size_to_create;

        if(_rvm_try_load_from_backing_store(rvm, new_segment) == FALSE)
        {
            _rvm_create_backing_store_for_segment(rvm, new_segment);
        }
        if(_rvm_segment_is_in_redo_log(rvm, new_segment, &redo_log,
                    &segment_entry_redo_log_index) == TRUE)
        {
            _rvm_patch_up_segment_with_redo_log(redo_log, new_segment,
                    segment_entry_redo_log_index);
            _rvm_save_segment(rvm, new_segment);
            _rvm_remove_segment_from_redo_log(redo_log, new_segment);
            _rvm_save_redo_log(rvm, redo_log);
            free(redo_log->entries);
            free(redo_log);
        }
        steque_init(&new_segment->mods);
        seqsrchst_put(&rvm->segst, new_segment->segbase, new_segment);
        /*
        fprintf(stderr, "When mapping new region, base %p points to %p; %p\n",
                new_segment->segbase, new_segment,
                seqsrchst_get(&rvm->segst, return_value));
                */
    }else
    {
        fprintf(stderr, "Segment name too long: '%s' @ %lu characters\n",
                segname, strlen(segname));
        exit(1);
    }
    /* Debugging
    fprintf(stderr, "Mapped new region: %p\n", return_value);
    */
    return return_value;
}

/* rvm_unmap
 *
 * Unmap a segment from memory.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param void* segbase: the base address to deallocate
 */
void rvm_unmap(rvm_t rvm, void *segbase)
{
    segment_t requested_segment = seqsrchst_delete(&rvm->segst, segbase);
    /* Debugging
    fprintf(stderr, "rvm_unmap %s\n", requested_segment->segname);
    */

    if(requested_segment->cur_trans != NULL)
    {
        rvm_abort_trans(requested_segment->cur_trans);
    }
    steque_destroy(&requested_segment->mods);
    free(segbase);
    free(requested_segment);
}
/* rvm_destroy
 * Destroy a segment completely, erasing its backing store. This function
 * should not be called on a segment that is currently mapped.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param const char* segname: the name of the segment to delete
 */
void rvm_destroy(rvm_t rvm, const char *segname)
{
    char* backing_store_file_name = _rvm_get_full_file_name(rvm,
                                                            (char*)segname);
    fprintf(stderr, "rvm_destroy %s\n", segname);
    if(unlink(backing_store_file_name) != 0 && errno != ENOENT)
    {
        fprintf(stderr, "Error while deleting backing store %s: %s\n",
                segname, strerror(errno));
        exit(1);
    }
    free(backing_store_file_name);
}
/* rvm_begin_transaction
 *
 * Begin a transaction that will modify the segments listed in segbases. If any
 * of the specified segments is already being modified by a transaction, then
 * the call should fail and return (trans_t) -1. Note that trant_t needs to be
 * able to be typecasted to an integer type.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 * @param int numsegs: the number of segment base pointers in the segbases
 *      array
 * @param void** segbases: segment base address which should be included within
 *      this transaction
 * @returns trans_t describing a new transaction which has begun
 */
trans_t rvm_begin_trans(rvm_t rvm, int numsegs, void **segbases)
{
    uint8_t encountered_segment_already_in_transaction = FALSE;
    int rollback_segment_base_index = 0;
    int current_segment_base_index = 0;
    void* current_segment_base = segbases[current_segment_base_index];
    segment_t current_segment;
    trans_t new_transaction = _rvm_create_new_transaction(rvm);
    /* Debugging
    fprintf(stderr, "begin %d transaction @ %p\n", numsegs,
            current_segment_base);
            */
    while(current_segment_base_index < numsegs &&
            encountered_segment_already_in_transaction == FALSE)
    {
        current_segment = seqsrchst_get(&rvm->segst, current_segment_base);
        if(current_segment->cur_trans == NULL)
        {
            /* Debugging
            fprintf(stderr, "Beginning transaction on segment %p (%s) at %p\n",
                    current_segment, current_segment->segname, current_segment);
                    */

            current_segment->cur_trans = new_transaction;
            _rvm_add_segment_to_transaction(current_segment, new_transaction);

            current_segment_base_index += 1;
            if(current_segment_base_index < numsegs)
            {
                current_segment_base = segbases[current_segment_base_index];
            }
        }else
        {
            /* Debugging
            fprintf(stderr, "Segment %s already in transaction: %p\n",
                    current_segment->segname, current_segment->cur_trans);
                    */
            encountered_segment_already_in_transaction = TRUE;
        }
    }
    if(encountered_segment_already_in_transaction == TRUE)
    {
        _rvm_free_transaction(new_transaction);
        current_segment_base_index = 0;
        current_segment_base = segbases[rollback_segment_base_index];
        while(rollback_segment_base_index < current_segment_base_index)
        {
            current_segment = seqsrchst_get(&rvm->segst, current_segment);
            current_segment->cur_trans = NULL;
            rollback_segment_base_index += 1;
            if(rollback_segment_base_index < current_segment_base_index)
            {
                current_segment_base = segbases[current_segment_base_index];
            }
        }
        new_transaction = -1;
    }
    /* Debugging
    fprintf(stderr, "Started transaction %p\n", new_transaction);
    */
    return new_transaction;
}
/* rvm_about_to_modify
 *
 * Declare that the library is about to modify a specified range of memory in
 * the specified segment. The segment must be one of the segments specified in
 * the call to rvm_begin_trans. Your library needs to ensure that the old
 * memory has been saved, in case an abort is executed. It is legal call
 * rvm_about_to_modify multiple times on the same memory area.
 *
 * @param trans_t tid: the transaction which this segbase is associated with
 * @param void* segbase: the base pointer of this segment
 * @param int offset: the offset within the memory segment which is desired
 * @param int size: the size past the offset which is set to be modified
 */
void rvm_about_to_modify(trans_t tid, void *segbase, int offset, int size)
{
    /* Debugging
    fprintf(stderr, "About to modify %d@%p+%d with transaction %p\n",
            size, segbase, offset, tid);
            */
    mod_t* modification_area = NULL;
    segment_t to_be_modified_segment = seqsrchst_get(&tid->rvm->segst,
                                                     segbase);
    if(to_be_modified_segment != NULL)
    {
        modification_area = malloc(sizeof(mod_t));
        modification_area->offset = offset;
        modification_area->size = size;
        modification_area->undo = malloc(size);
        memcpy(modification_area->undo, segbase + offset, size);
        steque_enqueue(&to_be_modified_segment->mods, modification_area);
        /* Debugging
        fprintf(stderr, "\tAdded modification_area %d@%p+%d, base %p(%s) now "
                "has %d undo\n", modification_area->size, modification_area,
                modification_area->offset,
                to_be_modified_segment->segbase,
                to_be_modified_segment->segname,
                steque_size(&to_be_modified_segment->mods));
                */
    }else
    {
        fprintf(stderr, "Requested segment at %p not found\n", segbase);
        exit(1);
    }
}
/* rvm_commit_trans
 *
 * Commit all changes that have been made within the specified transaction.
 * When the call returns, then enough information should have been saved to
 * disk so that, even if the program crashes, the changes will be seen by the
 * program when it restarts.
 *
 * @param trans_t tid: the transaction whose modification should be committed
 */
void rvm_commit_trans(trans_t tid)
{
    int current_segment_index = 0;
    segment_t current_segment = tid->numsegs == 0 ?
        NULL : tid->segments[current_segment_index];

    /* Debugging
    fprintf(stderr, "Commit transaction %p with %d segments\n", tid,
            tid->numsegs);
            */
    redo_t redo_log = _rvm_get_redo_log(tid->rvm);
    /* Debugging
    fprintf(stderr, "Got redo log '%s'@%p\n", tid->rvm->prefix, redo_log);
    _rvm_print_redo_log(redo_log);
    */
    while(current_segment != NULL)
    {
        /* Debugging
        fprintf(stderr, "\tSegment %s has %d modifications\n",
                current_segment->segname, steque_size(&current_segment->mods));
                */
        if(steque_size(&current_segment->mods) > 0)
        {
            _rvm_add_segment_to_redo_log(redo_log, current_segment);
            current_segment->cur_trans = NULL;
        }else
        {
            /* Debugging
            fprintf(stderr, "\t\tReloading segment %s from backing store\n",
                    current_segment->segname);
                    */
            _rvm_try_load_from_backing_store(tid->rvm, current_segment);
            _rvm_patch_up_segment_with_redo_log(redo_log, current_segment,
                                                current_segment_index);
            current_segment->cur_trans = NULL;
        }
        current_segment_index += 1;
        if(current_segment_index < tid->numsegs)
        {
            current_segment = tid->segments[current_segment_index];
        }else
        {
            current_segment = NULL;
        }
    }
    _rvm_save_redo_log(tid->rvm, redo_log);
}
/* rvm_abort_trans
 *
 * Undo all changes that have happened within the specified transaction.
 *
 * @param trans_t tid: the transaction to abort
 */
void rvm_abort_trans(trans_t tid)
{
    int current_segment_index = 0;
    mod_t* current_modification = NULL;
    segment_t current_segment = NULL;
    redo_t redo_log = _rvm_get_redo_log(tid->rvm);
    /* Debugging
    fprintf(stderr, "Aborting transaction size %d\n", tid->numsegs);
    */
    for(current_segment_index = 0; current_segment_index < tid->numsegs;
            current_segment_index += 1)
    {
        current_segment = tid->segments[current_segment_index];
        /*
        fprintf(stderr, "\tSegment %s has %d modifications\n",
                current_segment->segname, steque_size(&current_segment->mods));
                */
        while(steque_size(&current_segment->mods) > 0)
        {
            current_modification = steque_pop(&current_segment->mods);
            /*
            fprintf(stderr, "\t\tmodification %d@%p+%d\n",
                    current_modification->size,
                    current_segment->segbase,
                    current_modification->offset);

            hexDump("Aborting",
                    current_segment->segbase + current_modification->offset,
                    100);
                    */
            memcpy(current_segment->segbase + current_modification->offset,
                    current_modification->undo,
                    current_modification->size);
            /*
            hexDump("Restored",
                    current_segment->segbase + current_modification->offset,
                    100);
                    */
            free(current_modification->undo);
            free(current_modification);
        }
        _rvm_remove_segment_from_redo_log(redo_log, current_segment);
        current_segment->cur_trans = NULL;
        /*
        fprintf(stderr, "\tSegment %s now has %d modifications\n",
                current_segment->segname, steque_size(&current_segment->mods));
                */
    }
    _rvm_save_redo_log(tid->rvm, redo_log);
    free(redo_log->entries);
    free(redo_log);
}
/* rvm_truncate_log
 *
 * Play through any committed or aborted items in the log file(s) and shrink
 * the log file(s) as much as possible.
 *
 * @param rvm_t rvm: recoverable virtual memory context structure
 */
void rvm_truncate_log(rvm_t rvm)
{
    int current_entry_idx = 0;
    segentry_t* update_source = NULL;
    segment_t to_be_updated = NULL;
    redo_t to_be_truncated = _rvm_get_redo_log(rvm);
    /* Debugging
    fprintf(stderr, "Truncating redo log length %d\n",
            to_be_truncated->numentries);
            */
    if(to_be_truncated->numentries > 0)
    {
        update_source = &to_be_truncated->entries[current_entry_idx];
        while(current_entry_idx < to_be_truncated->numentries)
        {
            to_be_updated = _rvm_get_segment_by_name(rvm,
                                                     update_source->segname);
            _rvm_patch_up_segment_with_redo_log(to_be_truncated, to_be_updated,
                                                current_entry_idx);
            _rvm_save_segment(rvm, to_be_updated);
            _rvm_remove_segment_from_redo_log(to_be_truncated, to_be_updated);
            current_entry_idx += 1;
            if(current_entry_idx < to_be_truncated->numentries)
            {
                update_source = &to_be_truncated->entries[current_entry_idx];
            }
        }
        _rvm_save_redo_log(rvm, to_be_truncated);
    }
    free(to_be_truncated->entries);
    free(to_be_truncated);
}
