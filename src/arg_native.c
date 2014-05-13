/* -*- c-file-style: "java"; indent-tabs-mode: nil; tab-width: 4; fill-column: 78 -*-
 *
 * distcc -- A simple distributed compiler system
 *
 * Copyright 2013 Andrew Savchenko <bircoph@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */


           /* The chief enemy of creativity is "good" sense
            *                                      -- Picasso */


/**
 * @file
 *
 * Functions for -m$arg=native argument expansion.
 *
 * Instead of compiling -march=native locally (as well as -mtune=native and
 * -mcpu=native) we can extract expansion of native parameter from
 * gcc output in a way similar to:
 * $ gcc -march=native -E -v - < /dev/null 2>&1 | egrep "\-E -quiet -v" |
 *   sed 's/.*-E -quiet -v - //'
 *
 * Results are per-compiler cached. Compiler is identified by mtime
 * and size.
 *
 * -march supersedes -mcpu and -mcpu supersedes -mtune, so all args
 * should be parsed before actual expansion.
 **/


#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "distcc.h"
#include "trace.h"
#include "exitcode.h"
#include "snprintf.h"

/**
 * Search compiler based on its basename.
 *
 * First try to get PATH. If it is undefined or emphy, try to get
 * system defaults from confstr().
 *
 * @param name      Compiler base name.
 * @param fullname  Returned found full name.
 * 
 * @return dcc standard exit code
 **/
static int
dcc_search_compiler_in_path(const char *name, char **fullname)
{
    char *envpath;
    char *token, *saveptr, *str;
    int envpath_size = 256;
    int ret;
    int need4free = 0;  // do we need to free envpath?
                        // it can't be touched after getenv, but must
                        // be after confstr

    /* Look for PATH */
    if (!(envpath = getenv("PATH")) || !strlen(envpath)) {
        // Strange, but legal: we have PATH undefined or empty
        rs_trace("PATH seems to be not defined");
        
        // try to get from standard configuration,
        // will result in something like "/bin:/usr/bin"
        envpath = malloc(envpath_size * sizeof(char));
        if (!(envpath = malloc(envpath_size * sizeof(char)))) {
            rs_log_error("failed to allocate PATH buffer");
            return EXIT_OUT_OF_MEMORY;
        }
        need4free = 1;

        ret = confstr(_CS_PATH, envpath, envpath_size);
        if (ret > envpath_size) {
            // Strange, but legal: too long default PATH
            if (!(envpath = realloc(envpath, ret * sizeof(char)))) {
                rs_log_error("failed to reallocate PATH buffer");
                return EXIT_OUT_OF_MEMORY;
            }
            envpath_size = ret;
            // Recall with full path
            confstr(_CS_PATH, envpath, envpath_size);
        }
        if (!(confstr(_CS_PATH, envpath, ret))) {
            rs_log_error("confstr() says PATH have no value");
            return EXIT_COMPILER_MISSING;
        }
    }

    /* Parse PATH string */
    ret = EXIT_COMPILER_MISSING;
    str = strdup(envpath);  // copy as will need to modify
    while ((token = strtok_r(str, ":", &saveptr))) {
        // construct full name to check
        if (asprintf(fullname, "%s/%s", token, name) == -1) {
            rs_log_error("asprintf failed for compiler fullname");
            return EXIT_OUT_OF_MEMORY;
        }

        if (!access(*fullname, X_OK)) {
            // found it!
            rs_trace("compiler found: %s", *fullname);
            ret = 0;
            break;
        }
        str = NULL;
    }

    if (need4free)
        free(envpath);
    return ret;
}

/**
 * Search compiler and get its ID: size, mtime in form of a hash
 * string. This should be reliable enough for compiler change
 * detection.
 *
 * @param name Compiler name.
 * @param hash Found hash value. Must be freed by caller.
 *
 * @return dcc standard exit code
 **/
static inline int
dcc_get_compiler_id(const char *name, char **hash)
{
    char *fullname;
    int ret;
    int need4free = 1; // do we need to free fullname?
    struct stat statbuf;

    /* Look for full name first */
    if (name[0] == '/') {
        if (!access(name, X_OK)) {
            fullname = (char*)name;
            need4free = 0;
        } else {
            rs_log_warning("compiler is not accessible by its full name '%s' : %s",
                name, strerror(errno));
            // If compiler is not found by a full name, it may be
            // somewhere else, so try PATH as fallback.
            // Strip dirname before proceed further.
            if (( ret = dcc_search_compiler_in_path(basename(name), &fullname) ))
                return ret;
        }
    } else {
        if (( ret = dcc_search_compiler_in_path(name, &fullname) ))
            return ret;
    }

    /* Get ID data */
    if (stat(fullname, &statbuf) == -1) {
        rs_log_error("failed to stat compiler '%s': %s", fullname, strerror(errno));
        return EXIT_COMPILER_MISSING;
    }

    /* Generate compiler hash: hex(size, mtime)*/
    if (asprintf(hash, "%lx%lx", statbuf.st_size, statbuf.st_mtime) == -1) {
        rs_log_error("can't generate compiler's hash");
        return EXIT_OUT_OF_MEMORY;
    }
    rs_trace("compiler is %s, hash is %s", fullname, *hash);

    if (need4free)
        free(fullname);
    return 0;
}

/**
 * Generate cache path and file name based on compiler's hash and
 * native type.
 *
 * Cache is stored at $DISTCC_DIR/cache/$hash-$type ,
 * where type is a charfield "act" corresponding to -march, -mcpu
 * and -mtune options present (with native argument).
 *
 * @note
 * A complicate thing here is that on different architectures
 * different combinations of these options may provide different
 * non-additive results. E.g. expanded options from -march, -mcpu
 * and -march -mcpu (together) may yield three different results -
 * that's why we need to cache them separately. Though order of
 * options doesn't matter, thus we have seven cases left :)
 *
 * @param ret_hash Compiler hash. Full hash name is returned by this
 * variable too.
 * @param type Bitmask of requested native type.
 * 
 * @return dcc standard exit code
 **/
static inline int
dcc_get_hash_filename(char **ret_hash, const int type)
{
    int hash_len, ret;
    char *hash = *ret_hash;
    char *cachedir;
    char *hashname;

    // Grow hash array to adapt the longest possible extension:
    // "-act"
    hash_len = strlen(hash);
    // 4 bytes for extension + 1 for '\0'
    if (!(hash = realloc(hash, (hash_len + 5) * sizeof(char)))) {
        rs_log_error("failed to reallocate PATH buffer");
        return EXIT_OUT_OF_MEMORY;
    }

    /* Add hash name extension based on its type. */
    hash[hash_len++] = '-';
    if (type & DCC_ARG_MARCH)
        hash[hash_len++] = 'a';
    if (type & DCC_ARG_MCPU)
        hash[hash_len++] = 'c';
    if (type & DCC_ARG_MTUNE)
        hash[hash_len++] = 't';
    hash[hash_len++] = '\0';

    /* Get cache directory */
    if (dcc_get_cache_dir(&cachedir)) {
        rs_log_error("can't get cache directory");
        *ret_hash = hash;
        return EXIT_IO_ERROR;
    }

    // construct full hash name
    if (asprintf(&hashname, "%s/%s", cachedir, hash) == -1) {
        rs_log_error("asprintf failed for hash full name");
        *ret_hash = hash;
        ret = EXIT_OUT_OF_MEMORY;
    } else {
        free(hash);
        *ret_hash = hashname;
        ret = 0;
    }

    free(cachedir);

    return ret;
}

/**
 * Split string into argv array.
 *
 * @param str   String to split
 * @param ret_argv  Pointer to argv array
 * @param ret_argc  Pointer to argv size (not including last NULL
 * element)
 *
 * @return dcc standard exit code
 * Error is also returned if no elements were found, 
 * argv is cleared in this case.
 **/
static int
dcc_str_to_argv(char *str, char ***ret_argv, int *ret_argc)
{
    const char *delim = " \t\v\n\r";    // possible field delimitors
    char *saveptr, *token;
    int argv_size = 64;  // memory allocation size for argv, may be larger argc
    char **argv;
    int argc;

    argc = 0;
    // allocate initial argv buffer
    if (!(argv = malloc(sizeof(char*) * argv_size))) {
        rs_log_error("failed to allocate argv buffer");
        return EXIT_OUT_OF_MEMORY;
    }

    /* Convert string to argv array */
    for (argc = 0; (token = strtok_r(str, delim, &saveptr)); argc++, str = NULL) {
        // grow array as needed
        if (argc + 2 > argv_size) {
            argv_size *= 2;
            if (!(argv = realloc(argv, sizeof(char*) * argv_size))) {
                rs_log_error("failed to reallocate argv buffer");
                return EXIT_OUT_OF_MEMORY;
            }
        }
        // record new element
        argv[argc] = strdup(token);
    }
    argv[argc] = NULL;

    /* If list is empty, emit an error */
    if (!argc) {
        rs_log_error("argv string is empty!");
        dcc_free_argv(argv);
        argv = NULL;
        return EXIT_DISTCC_FAILED;
    }

    // return values
    *ret_argv = argv;
    *ret_argc = argc;

    return 0;
}

/**
 * Look for a cache file for present compiler and flag type.
 *
 * This function errors should be non-fatal for further proceeding.
 * Cache miss is OK.
 *
 * @param hash Compiler hash
 * @param argv Where to write argv
 * @param argc Where to write argc, terminating NULL is not
 * counted.
 *
 * @return dcc standard exit code
 **/
static inline int
dcc_cache_query(const char *hashname, char ***argv, int *argc)
{
    int ret;
    FILE *cache ;
    char *buf = NULL;
    size_t buf_size;

    if (!(cache = fopen(hashname, "r"))) {
        // File is not readable (or absent)
        rs_trace("can't open cache file %s : %s", hashname, strerror(errno));
        return EXIT_NO_SUCH_FILE;
    }

    // Get cache string
    if (getline(&buf, &buf_size, cache) == -1) {
        rs_log_error("cache %s is empty!", hashname);
        ret = EXIT_DISTCC_FAILED;
    } else {
        // split parameter list into argv array
        rs_log_info("cache found : %s", hashname);
        ret = dcc_str_to_argv(buf, argv, argc);
    }

    // cleanup
    if (fclose(cache))
        rs_log_error("can't close cache file %s : %s", hashname, strerror(errno));
    free(buf);

    return ret;
}

/**
 * Child process intended to run compiler sample in order to
 * extract -m<arg> expansion.
 *
 * @param name      Compiler name
 * @param type      -m<arg> type
 * @param pipefd    pipe descriptors
 *
 * @return never
 **/
static void NORETURN
dcc_compiler_query_child(const char *name, const int type, const int pipefd[])
{
    const char *args[8] = {NULL, "-E", "-v", "-", NULL, NULL, NULL, NULL};
    const char *args_m[3] = {"-march=native", "-mcpu=native", "-mtune=native"};
    int argsidx;
    int devnull;

    // do not read from pipe
    if (close(pipefd[0])) {
        rs_log_error("can't close child's pipe: %s", strerror(errno));
        exit(EXIT_IO_ERROR);
    }

    // redirect stdin and stdout to /dev/null
    if ((devnull = open("/dev/null", O_RDWR)) == -1) {
        rs_log_error("can't open /dev/null: %s", strerror(errno));
        exit(EXIT_IO_ERROR);
    }
    if (dup2(devnull, 0) == -1) {
        rs_log_error("can't redirect /dev/null to stdin: %s", strerror(errno));
        exit(EXIT_IO_ERROR);
    }
    if (dup2(devnull, 1) == -1) {
        rs_log_error("can't redirect stdout to /dev/null: %s", strerror(errno));
        exit(EXIT_IO_ERROR);
    }

    /* Prepare compiler args */
    args[0] = basename(name);
    argsidx = 4;    // first empty slot;
    if (type & DCC_ARG_MARCH)
        args[argsidx++] = args_m[0];
    if (type & DCC_ARG_MCPU)
        args[argsidx++] = args_m[1];
    if (type & DCC_ARG_MTUNE)
        args[argsidx++] = args_m[2];
    
    if (rs_trace_level >= RS_LOG_INFO)
        rs_log_info("running compiler query: %s %s", name, dcc_argv_tostr((char**)args));

    // write stderr to pipe
    if (dup2(pipefd[1], 2) == -1) {
        rs_log_error("can't dup2() stderr: %s", strerror(errno));
        exit(EXIT_IO_ERROR);
    }

    /* Run compiler */
    execvp(name, (char *const *)args);
    // We've failed. Try based on basename.
    execvp(args[0], (char *const *)args);
    exit(EXIT_COMPILER_MISSING);
}

/**
 * Get -m<arg>=native expansion from compiler output alike:
 * $ gcc -E -v - -march=native < /dev/null 2>&1
 * We need to parse stderr.
 * 
 * @param name Compiler name
 * @param argv argv storage
 * @param argc argv size
 * @param type Type of query to perform (march, mtune, mcpu)
 * 
 * @return dcc standard exit code
 **/
static inline int
dcc_compiler_query(const char *name, char ***argv, int *argc, const int type)
{
    int pipefd[2];  // pipe for gcc stderr
    pid_t cpid;     // child pid

    FILE *out;          // stderr output data from gcc
    char *buf = NULL;   // stderr buffer
    size_t buf_size;
    char *match;
    int ret;

    // prepare pipe to get stderr
    if (pipe(pipefd) == -1) {
        rs_log_error("failed to create pipe for compiler: %s", strerror(errno));
        return EXIT_IO_ERROR;
    }

    // here we go..
    if ((cpid = fork()) == -1) {
        rs_log_error("failed to fork for compiler: %s", strerror(errno));
        return EXIT_DISTCC_FAILED;
    }

    if (!cpid) {
        /* Child is here */
        dcc_compiler_query_child(name, type, pipefd);
    } else {
        /* Parent is here */

        // do not write to pipe
        if (close(pipefd[1])) {
            rs_log_error("can't close parent's pipe: %s", strerror(errno));
            return EXIT_IO_ERROR;
        }

        // open pipe from child
        if (!(out = fdopen(pipefd[0], "r"))) {
            rs_trace("can't open pipe from child : %s", strerror(errno));
            return EXIT_NO_SUCH_FILE;
        }

        /* Parse GCC output */
        ret = EXIT_DISTCC_FAILED; // in case we'll found nothing
        while (getline(&buf, &buf_size, out) != -1) {
            // grep for unique pattern
            if (!(match = strstr(buf, " - ")))
                continue;
            // convert to argv
            ret = dcc_str_to_argv(match + 3, argv, argc);
            break;
        }
        
        // cleanup
        if (fclose(out))
            rs_log_error("can't close pipe : %s", strerror(errno));
        free(buf);

        if (wait(NULL) == -1)
            rs_log_error("wait failed : %s", strerror(errno));
    }

    return ret;
}

/**
 * Save expanded "native" arguments to cache
 *
 * @param hash Filename to save hash to
 * @param argv argv array to save
 *
 * @return dcc standard exit code
 **/
static inline int
dcc_cache_write(const char *hash, const char **argv)
{
    FILE *cache;
    char *astr;
    int ret = 0;

    if (!(cache = fopen(hash, "w"))) {
        rs_trace("unable to create cache file %s : %s", hash, strerror(errno));
        return EXIT_IO_ERROR;
    }

    // write data to the file
    astr = dcc_argv_tostr((char**)argv);
    if (fputs(astr, cache) == EOF) {
        rs_log_error("can't write to cache file %s : %s", hash, strerror(errno));
        ret = EXIT_IO_ERROR;
    }

    if (fclose(cache)) {
        rs_log_error("can't close cache file %s : %s", hash, strerror(errno));
        ret = EXIT_IO_ERROR;
    }
    free(astr);

    if (!ret)
        rs_log_info("cache %s saved", hash);

    return ret;
}

/**
 * Insert native expansion into argv instead of first occurrence of
 * native flags, remove all other native encounters.
 *
 * A special pain here is that input and output filename indices in
 * the argv will be changed and must be recalculated.
 *
 * @param argv      Original list of arguments, must be freed by the caller.
 * @param exp_argv  Expanded list of arguments.
 * @param exp_argc  Size of exp_argv array.
 * @param input_idx     index of input file name in the argv
 * @param output_idx    index of output file name in the argv
 *
 * @return dcc standard exit code
 **/
static inline int 
dcc_insert_expansion(char ***argv, char ***ret_exp_argv, const int exp_argc,
    int *input_idx, int *output_idx)
{
    char **new_argv;    // buffer for new argv
    char **old_argv;    // pointer to old argv
    char **exp_argv;    // pointer to old argv
    char *astr;
    char *a;
    int inserted = 0;   // flag is set if expansion data is already inserted
    int i, j, k;

    // new array length <= old - 1(at least) + exp + 1
    if (!(new_argv = malloc((dcc_argv_len(*argv) + exp_argc) * sizeof(char*)))) {
        rs_log_error("failed to allocate argv for native expansion");
        return EXIT_OUT_OF_MEMORY;
    }

    // generate new argv
    old_argv = *argv;
    exp_argv = *ret_exp_argv;
    for (i = j = 0; (a = old_argv[i]); i++) {
        if (!strcmp(a, "-march=native") ||
            !strcmp(a, "-mtune=native") ||
            !strcmp(a, "-mcpu=native")) {
            // insert expansion only once
            if (!inserted) {
                for (k = 0; k < exp_argc; k++) {
                    // insert expansion in place of native arg
                    new_argv[j++] = exp_argv[k];
                }
                inserted = 1;

                // recalculate indices
                if (*input_idx > i)
                    *input_idx += exp_argc - 1;
                if (*output_idx > i)
                    *output_idx += exp_argc - 1;
            } else {
                // skip argument
                free(a);
                // recalculate indices
                if (*input_idx > i)
                    (*input_idx)--;
                if (*output_idx > i)
                    (*output_idx)--;

                continue;
            }
        } else {
            // copy all other args untouched
            new_argv[j++] = a;
        }
    }
    // terminate new argv by NULL element
    new_argv[j] = NULL;

    free(*argv);            // clean old arrays, but not their elements
    free(exp_argv);         // as they are put into new array;
    *ret_exp_argv = NULL;   // avoid double free later
    *argv = new_argv;

    // check for log level to avoid useless string manipulations
    if (rs_trace_level >= RS_LOG_INFO) {
        astr = dcc_argv_tostr(*argv);
        rs_log_info("argv after native expansion: %s", astr);
        free(astr);
    }

    return 0;
}

/**
 * Replace -m<arg>=native flag by its expansion string from
 * local compiler output or cache from previous queries, if
 * available.
 *
 * Supported args are: -march, -mcpu, -mtune. The former flag
 * supersedes the latter.
 *
 * All -m$arg=native arguments are removed from argv and the first
 * one is replaced by expansion of the highest priority flag found.
 *
 * A special pain here is that input and output filename indices in
 * the argv will be changed and must be recalculated.
 *
 * @param argv      argv, must be freed by the caller
 * @param type      denotes type of native argument (bitfield)
 * @param input_idx     index of input file name in the argv
 * @param output_idx    index of output file name in the argv
 *
 * @return dcc standard exit code
 **/
int
dcc_expand_native(char ***argv, const int type,
    int *input_idx, int *output_idx)
{
    char **exp_argv = NULL; // buffer for expanded native data
    int exp_argc = 0;       // length of expanded data
    char *compiler_name, *hash;
    int ret;

    // Lookup compiler ID (size + mtime)
    compiler_name = (*argv)[0];
    if ((ret = dcc_get_compiler_id(compiler_name, &hash))) {
        rs_log_error("failed to get compiler ID");
        return ret;
    }

    // Construct hash filename
    if ((ret = dcc_get_hash_filename(&hash, type))) {
        rs_log_error("failed to supply hash filename");
        goto cleanup;
    }

    /* Query expanded arguments from cache */
    if (dcc_cache_query(hash, &exp_argv, &exp_argc)) {
        // If cache is not available, grep compiler's output
        if (!(ret = dcc_compiler_query(compiler_name, &exp_argv, &exp_argc, type))) {
            // If grep is successful, record results to cache
            if (dcc_cache_write(hash, (const char**)exp_argv)) {
                rs_log_warning("can't save cache for compiler %s", compiler_name);
            }
        } else {
            rs_log_error("failed to expand native argument using compiler");
            goto cleanup;
        }
    }

    // Replace native args by found expansion
    ret = dcc_insert_expansion(argv, &exp_argv, exp_argc, input_idx, output_idx);

cleanup:
    free(hash);
    if (exp_argv)
        dcc_free_argv(exp_argv);

    return ret;
}
