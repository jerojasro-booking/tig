/* Copyright (c) 2006-2014 Jonas Fonseca <jonas.fonseca@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "tig/tig.h"
#include "tig/argv.h"
#include "tig/io.h"
#include "tig/watch.h"
#include "tig/options.h"
#include "tig/repo.h"
#include "tig/refdb.h"
#include "compat/hashtab.h"

static struct ref **refs = NULL;
static size_t refs_size = 0;
static struct ref *refs_head = NULL;

static struct ref_list **ref_lists = NULL;
static size_t ref_lists_size = 0;

//static GHashTable* commits_with_refs = NULL;
static htab_t hasht_commits_with_refs = NULL;

DEFINE_ALLOCATOR(realloc_refs, struct ref *, 256)
DEFINE_ALLOCATOR(realloc_refs_list, struct ref *, 8)
DEFINE_ALLOCATOR(realloc_ref_lists, struct ref_list *, 8)

static int
compare_refs(const void *ref1_, const void *ref2_)
{
	const struct ref *ref1 = *(const struct ref **)ref1_;
	const struct ref *ref2 = *(const struct ref **)ref2_;

	return ref_compare(ref1, ref2);
}

int
ref_compare(const struct ref *ref1, const struct ref *ref2)
{
	if (ref1->type != ref2->type)
		return ref1->type - ref2->type;
	return strcmp_numeric(ref1->name, ref2->name);
}

static int
ref_canonical_compare(const struct ref *ref1, const struct ref *ref2)
{
	int tag_diff = !!ref_is_tag(ref2) - !!ref_is_tag(ref1);

	if (tag_diff)
		return tag_diff;
	if (ref1->type != ref2->type)
		return !tag_diff ? ref1->type - ref2->type : ref2->type - ref1->type;
	return strcmp_numeric(ref1->name, ref2->name);
}

void
foreach_ref(bool (*visitor)(void *data, const struct ref *ref), void *data)
{
	size_t i;

	for (i = 0; i < refs_size; i++)
		if (refs[i]->id[0] && !visitor(data, refs[i]))
			break;
}

static hashval_t
id_ref_hash(const void *node)
{
	hashval_t val = htab_hash_string(((const struct ref*) node)->id);
	return val;
}

static hashval_t
id_ref_list_hash(const void *node)
{
	hashval_t val = htab_hash_string(((const struct ref_list*) node)->id);
	return val;
}

static hashval_t
name_ref_hash(const void *node)
{
	hashval_t val = htab_hash_string(((const struct ref*) node)->name);
	return val;
}

static int
id_ref_eq(const void *entry, const void *element)
{
	return strcmp(((const struct ref *) entry)->id, ((const struct ref *) element)->id) == 0;
}

static int
id_ref_list_eq(const void *entry, const void *element)
{
	return strcmp(((const struct ref_list *) entry)->id, ((const struct ref_list *) element)->id) == 0;
}

static int
name_ref_eq(const void *entry, const void *element)
{
	return strcmp((const char*)((const struct ref *) entry)->name, (const char*)((const struct ref *) element)->name) == 0;
}

static void
id_ref_delete(struct ref *node)
{
	free(node);
}

static void
key_del(void *key)
{
	id_ref_delete((struct ref *) key);
}
struct ref *
get_ref_head()
{
	return refs_head;
}

struct ref_list *
get_ref_list(const char *id)
{
	struct ref_list *list;
	size_t i;
	if (!hasht_commits_with_refs) {
		// TODO dealloc the hash table
		uint size = 500;
		hasht_commits_with_refs = htab_create_alloc(size, id_ref_hash, id_ref_eq, NULL, calloc, free);
		//commits_with_refs = g_hash_table_new(g_str_hash, g_str_equal);

		for (i = 0; i < refs_size; i++) {
			list = (struct ref_list*) htab_find(hasht_commits_with_refs, refs[i]);

			if (!list) {
				list = calloc(1, sizeof(*list));
				if (!list)
					return NULL;
				string_copy_rev(list->id, refs[i]->id);
				//g_hash_table_insert(commits_with_refs, (gpointer*)refs[i]->id, list);

				void **slot_id = htab_find_slot(hasht_commits_with_refs, refs[i], INSERT);
				if (slot_id != NULL && *slot_id == NULL) {
					*slot_id = list;
				}
			}
			if (realloc_refs_list(&list->refs, list->size, 1))
				list->refs[list->size++] = refs[i];
		}
	}

	struct ref r_key;
	string_copy_rev(r_key.id, id);
	list = (struct ref_list*) htab_find(hasht_commits_with_refs, &r_key);
	if (!list) {
		return NULL;
	}

	qsort(list->refs, list->size, sizeof(*list->refs), compare_refs);

	FILE* fp = fopen("/home/dfranca/debug.out", "a");
	for (i=0; i < list->size; i++) {
		fprintf(fp, "\n\nID: %s\n", list->refs[i]->id);
		fprintf(fp, "NAME: %s\n", list->refs[i]->name);
	}
	fclose(fp);

	return list;
}

struct ref *
get_canonical_ref(const char *id)
{
	struct ref_list *list = get_ref_list(id);
	struct ref *ref = NULL;
	size_t i;

	for (i = 0; list && i < list->size; i++)
		if (!ref || ref_canonical_compare(list->refs[i], ref) < 0)
			ref = list->refs[i];

	return ref;
}

struct ref_opt {
	const char *remote;
	const char *head;
	enum watch_trigger changed;
};

static void
done_ref_lists(void)
{
	int i;

	for (i = 0; i < ref_lists_size; i++) {
		struct ref_list *list = ref_lists[i];

		free(list->refs);
		free(list);
	}

	free(ref_lists);
	ref_lists = NULL;
	ref_lists_size = 0;
}


static int
add_to_refs(const char *id, size_t idlen, char *name, size_t namelen, struct ref_opt *opt)
{
	struct ref *ref = NULL;
	enum reference_type type = REFERENCE_BRANCH;
	int pos;
	static htab_t hasht_id;
	static htab_t hasht_name;

	if (!prefixcmp(name, "refs/tags/")) {
		type = REFERENCE_TAG;
		if (!suffixcmp(name, namelen, "^{}")) {
			namelen -= 3;
			name[namelen] = 0;
		} else {
			type = REFERENCE_LOCAL_TAG;
		}

		namelen -= STRING_SIZE("refs/tags/");
		name	+= STRING_SIZE("refs/tags/");

	} else if (!prefixcmp(name, "refs/remotes/")) {
		type = REFERENCE_REMOTE;
		namelen -= STRING_SIZE("refs/remotes/");
		name	+= STRING_SIZE("refs/remotes/");
		if (!strcmp(opt->remote, name))
			type = REFERENCE_TRACKED_REMOTE;

	} else if (!prefixcmp(name, "refs/replace/")) {
		type = REFERENCE_REPLACE;
		id	= name + strlen("refs/replace/");
		idlen	= namelen - strlen("refs/replace/");
		name	= "replaced";
		namelen	= strlen(name);

	} else if (!prefixcmp(name, "refs/heads/")) {
		namelen -= STRING_SIZE("refs/heads/");
		name	+= STRING_SIZE("refs/heads/");
		if (strlen(opt->head) == namelen &&
		    !strncmp(opt->head, name, namelen))
			type = REFERENCE_HEAD;

	} else if (!strcmp(name, "HEAD")) {
		/* Handle the case of HEAD not being a symbolic ref,
		 * i.e. during a rebase. */
		if (*opt->head)
			return OK;
		type = REFERENCE_HEAD;
	}

	/* If we are reloading or it's an annotated tag, replace the
	 * previous SHA1 with the resolved commit id; relies on the fact
	 * git-ls-remote lists the commit id of an annotated tag right
	 * before the commit id it points to. */
	int replace = type == REFERENCE_REPLACE;

	if (refs_size == 0) {
		uint size = 500;
		hasht_id = htab_create_alloc(size, id_ref_hash, id_ref_eq, key_del, calloc, free);
		hasht_name = htab_create_alloc(size, name_ref_hash, name_ref_eq, key_del, calloc, free);
	}

	struct ref *r = (struct ref*)calloc(1, sizeof(*ref) + namelen);

	strcpy(r->id, id);
	strcpy(r->name, name);
	
	if (replace) {
		ref = (struct ref*)htab_find(hasht_id, r);
	}
	else {
		ref = (struct ref*)htab_find(hasht_name, r);
	}

	if (!ref) {
		if (!realloc_refs(&refs, refs_size, 1))
			return ERR;
		ref = calloc(1, sizeof(*ref) + namelen);
		if (!ref)
			return ERR;
		refs[refs_size++] = ref;

		//Insert into the hash
		void **slot_id = htab_find_slot(hasht_id, r, INSERT);
		if (slot_id != NULL && *slot_id == NULL) {
			*slot_id = ref;
		}

		void **slot_name = htab_find_slot(hasht_name, r, INSERT);
		if (slot_name != NULL && *slot_name == NULL) {
			*slot_name = ref;
		}

		strncpy(ref->name, name, namelen);
	}

	if (strncmp(ref->id, id, idlen))
		opt->changed |= WATCH_REFS;

	ref->valid = TRUE;
	ref->type = type;
	string_ncopy_do(ref->id, SIZEOF_REV, id, idlen);

	if (type == REFERENCE_HEAD) {
		if (!refs_head ||
		    (refs_head != ref && memcmp(refs_head, ref, sizeof(*ref))))
			opt->changed |= WATCH_HEAD;
		refs_head = ref;
	}
	return OK;
}

static int
read_ref(char *id, size_t idlen, char *name, size_t namelen, void *data)
{
	return add_to_refs(id, idlen, name, namelen, data);
}

static int
reload_refs(bool force)
{
	const char *ls_remote_argv[SIZEOF_ARG] = {
		"git", "ls-remote", repo.git_dir, NULL
	};
	static bool init = FALSE;
	struct ref_opt opt = { repo.remote, repo.head, WATCH_NONE };
	struct repo_info old_repo = repo;
	size_t i;

	if (!init) {
		if (!argv_from_env(ls_remote_argv, "TIG_LS_REMOTE"))
			return ERR;
		init = TRUE;
	}

	if (!*repo.git_dir)
		return OK;

	if (force || !*repo.head)
		load_repo_head();

	if (strcmp(old_repo.head, repo.head))
		opt.changed |= WATCH_HEAD;

	refs_head = NULL;
	for (i = 0; i < refs_size; i++)
		refs[i]->valid = 0;

	done_ref_lists();

	if (io_run_load(ls_remote_argv, "\t", read_ref, &opt) == ERR)
		return ERR;

	for (i = 0; i < refs_size; i++)
		if (!refs[i]->valid) {
			refs[i]->id[0] = 0;
			opt.changed |= WATCH_REFS;
		}


	if (opt.changed)
		watch_apply(NULL, opt.changed);
	qsort(refs, refs_size, sizeof(*refs), compare_refs);

	return OK;
}

int
load_refs(bool force)
{
	static bool loaded = FALSE;

	if (!force && loaded)
		return OK;

	loaded = TRUE;
	return reload_refs(force);
}

int
add_ref(const char *id, char *name, const char *remote_name, const char *head)
{
	struct ref_opt opt = { remote_name, head };

	return add_to_refs(id, strlen(id), name, strlen(name), &opt);
}

void
ref_update_env(struct argv_env *env, const struct ref *ref, bool clear)
{
	if (clear)
		env->tag[0] = env->remote[0] = env->branch[0] = 0;

	string_copy_rev(env->commit, ref->id);

	if (ref_is_tag(ref)) {
		string_ncopy(env->tag, ref->name, strlen(ref->name));

	} else if (ref_is_remote(ref)) {
		const char *sep = strchr(ref->name, '/');

		if (!sep)
			return;
		string_ncopy(env->remote, ref->name, sep - ref->name);
		string_ncopy(env->branch, sep + 1, strlen(sep + 1));

	} else if (ref->type == REFERENCE_BRANCH) {
		string_ncopy(env->branch, ref->name, strlen(ref->name));
	}
}

static struct ref_format **ref_formats;

const struct ref_format *
get_ref_format(struct ref *ref)
{
	static const struct ref_format default_format = { "", "" };

	if (ref_formats) {
		struct ref_format *format = ref_formats[ref->type];

		if (!format && ref_is_tag(ref))
			format = ref_formats[REFERENCE_TAG];
		if (!format && ref_is_remote(ref))
			format = ref_formats[REFERENCE_REMOTE];
		if (!format)
			format = ref_formats[REFERENCE_BRANCH];
		if (format)
			return format;
	}

	return &default_format;
}

static enum status_code
parse_ref_format_arg(const char *arg, const struct enum_map *map)
{
	size_t arglen = strlen(arg);
	const char *pos;

	for (pos = arg; *pos && arglen > 0; pos++, arglen--) {
		enum reference_type type;

		for (type = 0; type < map->size; type++) {
			const struct enum_map_entry *entry = &map->entries[type];
			struct ref_format *format;

			if (arglen < entry->namelen ||
			    string_enum_compare(pos, entry->name, entry->namelen))
				continue;

			format = malloc(sizeof(*format));
			if (!format)
				return ERROR_OUT_OF_MEMORY;
			format->start = strndup(arg, pos - arg);
			format->end = strdup(pos + entry->namelen);
			if (!format->start || !format->end) {
				free((void *) format->start);
				free((void *) format->end);
				free(format);
				return ERROR_OUT_OF_MEMORY;
			}

			ref_formats[type] = format;
			return SUCCESS;
		}
	}

	return error("Unknown ref format: %s", arg);
}

enum status_code
parse_ref_formats(const char *argv[])
{
	const struct enum_map *map = reference_type_map;
	int argc;

	if (!ref_formats) {
		ref_formats = calloc(reference_type_map->size, sizeof(struct ref_format *));
		if (!ref_formats)
			return ERROR_OUT_OF_MEMORY;
	}

	for (argc = 0; argv[argc]; argc++) {
		enum status_code code = parse_ref_format_arg(argv[argc], map);
		if (code != SUCCESS)
			return code;
	}

	return SUCCESS;
}

/* vim: set ts=8 sw=8 noexpandtab: */
