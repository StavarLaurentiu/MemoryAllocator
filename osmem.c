// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

#include <block_meta.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MMAP_THRESHOLD (128 * 1024)
#define META_SIZE sizeof(struct block_meta)
#define MAP_ANONYMOUS 0x20
#define CALLOC_THRESHOLD getpagesize()

// Tracks if the heap was initiated
int heap_init;

// Points to the memory block list
struct block_meta *head;

int threshold = MMAP_THRESHOLD;

struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)ptr - 1;
}

struct block_meta *find_free_block(size_t size)
{
	size_t min_size = INT_MAX;
	struct block_meta *current = head, *last = NULL;
	struct block_meta *best_fit = NULL;

	// Coalesce blocks if posible
	while (current && current->next) {
		if (current->status == STATUS_FREE &&
			current->next->status == STATUS_FREE) {
			current->size += current->next->size + META_SIZE;
			if (current->next->next)
				current->next->next->prev = current;
			current->next = current->next->next;
		} else {
			current = current->next;
		}
	}

	// Find the best fitted block
	current = head;
	while (current) {
		if (current->status == STATUS_FREE && current->size >= size &&
			current->size < min_size) {
			min_size = current->size;
			best_fit = current;
		}

		last = current;
		current = current->next;
	}

	// Split memory blocks if posible
	if (best_fit != NULL && best_fit->size - size >= META_SIZE + 1) {
		struct block_meta *new_block =
			(struct block_meta *)((void *)best_fit + size + META_SIZE);
		new_block->size = best_fit->size - size - META_SIZE;
		new_block->status = STATUS_FREE;
		new_block->next = best_fit->next;
		new_block->prev = best_fit;
		best_fit->next = new_block;
		best_fit->size = size;

		if (new_block->next)
			new_block->next->prev = new_block;
	}

	// If we have to extend the last block
	int last_extended = 0;

	if (best_fit == NULL && last->status == STATUS_FREE) {
		void *result = sbrk(size - last->size);

		if (result == (void *)-1)
			DIE(1, "sbrk");

		last->size += size - last->size;
		last_extended = 1;
		best_fit = last;
	}

	// If there is no avalaible free space then extend the list
	if (best_fit == NULL && !last_extended) {
		struct block_meta *new_block =
			(struct block_meta *)sbrk(size + META_SIZE);

		if (new_block == (void *)-1)
			DIE(1, "sbrk");

		new_block->next = NULL;
		new_block->size = size;
		new_block->prev = last;
		last->next = new_block;

		best_fit = new_block;
	}

	best_fit->status = STATUS_ALLOC;
	return best_fit;
}

void *os_malloc(size_t size)
{
	if (size <= 0) {
		heap_init = 1;
		return NULL;
	}

	// Align the size
	size = ALIGN(size);

	// The block which will be returned
	struct block_meta *ret_block = NULL;

	if (size + META_SIZE < (unsigned long)threshold) {
		// Prealloc the heap if it is the case
		if (heap_init == 0) {
			heap_init = 1;

			struct block_meta *block = (struct block_meta *)sbrk(0);

			if (block == (void *)-1)
				DIE(1, "sbrk");

			block = (struct block_meta *)sbrk(MMAP_THRESHOLD);

			if (block == (void *)-1)
				DIE(1, "sbrk");

			block->size = MMAP_THRESHOLD - META_SIZE;
			block->status = STATUS_FREE;
			block->next = NULL;
			block->prev = NULL;

			head = block;
		}

		// Find a suitable memory block
		ret_block = find_free_block(size);
	} else {
		// Request a block using mmap
		struct block_meta *request =
			mmap(NULL, size + ALIGN(META_SIZE), PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (request == (void *)-1)
			DIE(1, "mmap");

		// Get the last memory block
		struct block_meta *current = head, *last = NULL;

		while (current) {
			last = current;
			current = current->next;
		}

		// Add block in the list
		if (last != NULL) {
			last->next = request;
			request->prev = last;
			request->next = NULL;
		} else {
			head = request;
			request->prev = NULL;
			request->next = NULL;
		}

		request->size = size;
		request->status = STATUS_MAPPED;

		ret_block = request;
	}

	return (void *)(ret_block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = get_block_ptr(ptr);

	if (block->status == STATUS_MAPPED) {
		int result = munmap(block, block->size + META_SIZE);

		head = NULL;

		if (result == -1)
			DIE(1, "munmap");
	} else {
		block->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	// Implement calloc by using malloc function, changing the threshold
	threshold = CALLOC_THRESHOLD;
	void *alloc_zone = os_malloc(nmemb * size);

	threshold = MMAP_THRESHOLD;
	memset(alloc_zone, 0, nmemb * size);

	return alloc_zone;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		heap_init = 1;
		os_free(ptr);
	}

	struct block_meta *block = get_block_ptr(ptr);

	// If realloc is called on a STATUS_FREE block
	if (block->status == STATUS_FREE)
		return NULL;

	// If we have enough space to split a non-mmaped block
	if (block->size >= size && block->status != STATUS_MAPPED)
		return ptr;

	// Use os_malloc to find a new block
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;

	// Copy the payload
	memcpy(new_ptr, ptr, block->size);

	os_free(ptr);

	return new_ptr;
}
