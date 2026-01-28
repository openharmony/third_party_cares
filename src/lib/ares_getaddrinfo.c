/* MIT License
 *
 * Copyright (c) 1998, 2011, 2013 Massachusetts Institute of Technology
 * Copyright (c) 2017 Christian Ammer
 * Copyright (c) 2019 Andrew Selivanov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_private.h"

#ifdef HAVE_GETSERVBYNAME_R
#  if !defined(GETSERVBYNAME_R_ARGS) || (GETSERVBYNAME_R_ARGS < 4) || \
    (GETSERVBYNAME_R_ARGS > 6)
#    error "you MUST specify a valid number of arguments for getservbyname_r"
#  endif
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#include <assert.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "ares_dns.h"
#include "ares_llist.h"

struct host_query {
  ares_channel_t            *channel;
  char                      *name;
  unsigned short             port; /* in host order */
  ares_addrinfo_callback     callback;
  void                      *arg;
  struct ares_addrinfo_hints hints;
  int    sent_family; /* this family is what was is being used */
  size_t timeouts;    /* number of timeouts we saw for this request */
  char  *lookups; /* Duplicate memory from channel because of ares_reinit() */
  const char *remaining_lookups; /* types of lookup we need to perform ("fb" by
                                    default, file and dns respectively) */

  /* Search order for names */
  char      **names;
  size_t      names_cnt;
  size_t      next_name_idx;       /* next name index being attempted */

  struct ares_addrinfo *ai;        /* store results between lookups */
  unsigned short        qid_a;     /* qid for A request */
  unsigned short        qid_aaaa;  /* qid for AAAA request */

  size_t                remaining; /* number of DNS answers waiting for */

  /* Track nodata responses to possibly override final result */
  size_t                nodata_cnt;
#if OHOS_DNS_PROXY_BY_NETSYS
  char                  *src_addr;
  struct ares_process_info process_info;
  struct ares_addrinfo_node *ipv4LocalAddrAi;
#endif
};

static const struct ares_addrinfo_hints default_hints = {
  0,         /* ai_flags */
  AF_UNSPEC, /* ai_family */
  0,         /* ai_socktype */
  0,         /* ai_protocol */
};

/* forward declarations */
static ares_bool_t next_dns_lookup(struct host_query *hquery);

#if OHOS_DNS_PROXY_BY_NETSYS
#define MAX_RESULTS 32
#define MAX_CANON_NAME 256
#define SOURCE_FROM_CARES 2

typedef union {
    struct sockaddr sa;
    struct sockaddr_in6 sin6;
    struct sockaddr_in sin;
} ares_align_sock_addr;

typedef struct {
    uint32_t ai_flags;
    uint32_t ai_family;
    uint32_t ai_socktype;
    uint32_t ai_protocol;
    uint32_t ai_addrlen;
    ares_align_sock_addr ai_addr;
    char ai_canonName[MAX_CANON_NAME + 1];
} ares_cached_addrinfo;

typedef struct {
    char *host;
    char *serv;
    struct addrinfo *hint;
} ares_cache_key_param_wrapper;

static const struct ares_family_query_info empty_family_query_info = {
  -1, /* retCode */
  NULL, /* serverAddr */
  1,  /* isNoAnswer */
  0,  /* cname */
};

void ares_addrinfo_hints_to_addrinfo(const struct ares_addrinfo_hints *hints, struct addrinfo *out_hints) {
  if (hints == NULL || out_hints == NULL) {
    return;
  }
  memset(out_hints, 0, sizeof(struct addrinfo));
  out_hints->ai_flags = hints->ai_flags;
  out_hints->ai_family = hints->ai_family;
  out_hints->ai_socktype = hints->ai_socktype;
  out_hints->ai_protocol = hints->ai_protocol;
}

long long ares_get_now_time()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  long long timestamp = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
  return timestamp;
}
 
void free_process_info(struct ares_process_info process_info)
{
    struct ares_family_query_info ipv4Info = process_info.ipv4QueryInfo;
    struct ares_family_query_info ipv6Info = process_info.ipv6QueryInfo;
    if (ipv4Info.serverAddr) {
        ares_free(ipv4Info.serverAddr);
    }
    if (ipv6Info.serverAddr) {
        ares_free(ipv6Info.serverAddr);
    }
}

void ares_free_posix_addrinfo(struct addrinfo *head) {
  while (head != NULL) {
    struct addrinfo *current = head;
    head = head->ai_next;
    if (current->ai_addr) {
      ares_free(current->ai_addr);
    }
    ares_free(current);
  }
}

struct addrinfo *ares_addrinfo_to_addrinfo(const struct ares_addrinfo *res) {
  if (res == NULL) {
    return NULL;
  }

  struct addrinfo *head_res = ares_malloc(sizeof(struct addrinfo));
  if (head_res == NULL) {
    return NULL;
  }
  memset(head_res, 0, sizeof(struct addrinfo));

  struct addrinfo *now_node = head_res;
  for (struct ares_addrinfo_node *tmp = res->nodes; tmp != NULL; tmp = tmp->ai_next) {
    if (tmp->ai_addrlen > sizeof(ares_align_sock_addr)) {
      continue;
    }
    struct addrinfo *next_node = ares_malloc(sizeof(struct addrinfo));
    if (next_node == NULL) {
      ares_free_posix_addrinfo(head_res);
      return NULL;
    }
    memset(next_node, 0, sizeof(struct addrinfo));
    now_node->ai_next = next_node;
    now_node = next_node;

    next_node->ai_flags = tmp->ai_flags;
    next_node->ai_family = tmp->ai_family;
    next_node->ai_socktype = tmp->ai_socktype;
    next_node->ai_protocol = tmp->ai_protocol;
    next_node->ai_addrlen = tmp->ai_addrlen;
    next_node->ai_addr = ares_malloc(sizeof(ares_align_sock_addr));
    if (next_node->ai_addr == NULL) {
      ares_free_posix_addrinfo(head_res);
      return NULL;
    }
    memset(next_node->ai_addr, 0, sizeof(ares_align_sock_addr));
    memcpy(next_node->ai_addr, tmp->ai_addr, tmp->ai_addrlen);
  }
  struct addrinfo *out_res = head_res->ai_next;
  ares_free(head_res);
  return out_res;
}

void ares_record_process(int status, const char *hostname, long long start_time,
    const struct ares_addrinfo *addr_info, struct host_query *hquery)
{
  if (hostname == NULL) {
    return;
  }
  int cost_time = ares_get_now_time() - start_time;
  struct ares_process_info process_info;
  process_info.ipv4QueryInfo = empty_family_query_info;
  process_info.ipv6QueryInfo = empty_family_query_info;
  process_info.sourceFrom = SOURCE_FROM_CARES;
  process_info.hostname = ares_strdup(hostname);
  if (addr_info) {
    // read from cache
    process_info.isFromCache = 1;
    process_info.queryTime = start_time;
    process_info.retCode = status;
    process_info.firstQueryEndDuration = cost_time;
    process_info.firstReturnType = 0;
    struct addrinfo *addr = ares_addrinfo_to_addrinfo(addr_info);
    ares_free_posix_addrinfo(addr);
    ares_free(process_info.hostname);
  } else if (!hquery) {
    // no hquery mean error
    process_info.isFromCache = 0;
    process_info.queryTime = start_time;
    process_info.retCode = status;
    process_info.firstQueryEndDuration = cost_time;
    process_info.firstReturnType = 0;
    ares_free(process_info.hostname);
  } else if (hquery) {
    // query complete
    ares_free(process_info.hostname);
    process_info = hquery->process_info;
    process_info.isFromCache = 0;
    struct addrinfo *addr = ares_addrinfo_to_addrinfo(hquery->ai);
    ares_free_posix_addrinfo(addr);
  }
}

int ares_ans_all_cname(const ares_dns_record_t *dnsrec)
{
  size_t ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  if (ancount == 0) {
    return 0;
  }
  for (size_t i = 0; i < ancount; i++) {
    const ares_dns_rr_t *rr =
      ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, i);
    ares_dns_rec_type_t rtype = ares_dns_rr_get_type(rr);
    ares_dns_class_t rclass = ares_dns_rr_get_class(rr);
    if (rclass != ARES_CLASS_IN || rtype != ARES_REC_TYPE_CNAME) {
      return 0;
    }
  }
  return 1;
}
 
char *ares_get_addr(struct ares_addr *addr)
{
  if (addr == NULL) {
    return NULL;
  }
  char *ip_str = NULL;
  if (addr->family == AF_INET) {
    ip_str = ares_malloc(INET_ADDRSTRLEN);
    if (ip_str == NULL) {
        return NULL;
    }
    if (ares_inet_ntop(AF_INET, &addr->addr.addr4, ip_str, INET_ADDRSTRLEN) == NULL) {
        ares_free(ip_str);
        return NULL;
    }
  } else if (addr->family == AF_INET6) {
    ip_str = ares_malloc(INET6_ADDRSTRLEN);
    if (ip_str == NULL) {
        return NULL;
    }
    if (ares_inet_ntop(AF_INET6, &addr->addr.addr6, ip_str, INET6_ADDRSTRLEN) == NULL) {
        ares_free(ip_str);
        return NULL;
    }
  }
  return ip_str;
}
 
char *ares_get_addr_by_sockaddr(struct sockaddr *sa)
{
  if (sa == NULL) {
    return NULL;
  }
  char *ip_str = NULL;
  switch (sa->sa_family) {
    case AF_INET: {
      ip_str = ares_malloc(INET_ADDRSTRLEN);
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      if (ares_inet_ntop(AF_INET, &sin->sin_addr, ip_str, INET_ADDRSTRLEN) == NULL) {
        ares_free(ip_str);
      }
      break;
    }
    case AF_INET6: {
      ip_str = ares_malloc(INET6_ADDRSTRLEN);
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
      if (ares_inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, INET6_ADDRSTRLEN) == NULL) {
        ares_free(ip_str);
      }
      break;
    }
    default:
      break;
  }
  return ip_str;
}
 
int ares_get_src_addr(ares_socket_t sock, struct ares_addr addr, struct sockaddr *src_addr)
{
  if (sock <= 0) {
    return -1;
  }
  ares_socklen_t len;
  switch (addr.family)
    {
    case AF_INET:
      len = sizeof(struct sockaddr_in);
      break;
    case AF_INET6:
      len = sizeof(struct sockaddr_in6);
      break;
    default:
      /* No known usable source address for non-INET families. */
      return -1;
    }
  if (getsockname(sock, src_addr, &len) != 0) {
    return -1;
  }
  return 0;
}
 
void ares_set_hquery_process(ares_dns_rec_type_t qtype, struct host_query *hquery,
  int status, struct ares_family_query_info info)
{
  if (hquery->process_info.firstQueryEndDuration == 0) {
    if (status == ARES_SUCCESS) {
        hquery->process_info.firstQueryEndDuration =
            ares_get_now_time() - hquery->process_info.queryTime;
    }
    hquery->process_info.firstReturnType = qtype;
  }
  if (qtype == ARES_REC_TYPE_A) {
    hquery->process_info.ipv4QueryInfo = info;
  }
  if (qtype == ARES_REC_TYPE_AAAA) {
    hquery->process_info.ipv6QueryInfo = info;
  }
}
 
void ares_parse_query_info(int status, const ares_dns_record_t *dnsrec, struct host_query *hquery)
{
  if (hquery == NULL || dnsrec == NULL || hquery->channel == NULL) {
    return;
  }
  ares_dns_rec_type_t qtype;
  const ares_channel_t *channel = hquery->channel;
  ares_query_t *query = ares_htable_szvp_get_direct(channel->queries_by_qid,
    ares_dns_record_get_id(dnsrec));
  if (query == NULL) {
    return;
  }
  if (ares_dns_record_query_get(query->query, 0, NULL, &qtype, NULL) != ARES_SUCCESS) {
    return;
  }
  if (qtype != ARES_REC_TYPE_A && qtype != ARES_REC_TYPE_AAAA)  {
    return;
  }
  char *res_addr = NULL;
  char *server_addr = NULL;
  ares_conn_t *conn = query->conn;
  if (conn == NULL) {
    return;
  }
  ares_server_t *server = conn->server;
  if (server == NULL) {
    return;
  }
  server_addr = ares_get_addr(&server->addr);
  struct sockaddr *src_addr = NULL;
  src_addr = ares_malloc(sizeof(struct sockaddr_storage));
  if (src_addr) {
    if (ares_get_src_addr(conn->fd, server->addr, src_addr) == 0) {
      res_addr = ares_get_addr_by_sockaddr(src_addr);
    }
  }
  ares_free(src_addr);
  hquery->src_addr = res_addr;
  struct ares_family_query_info info;
  info.retCode = status;
  size_t ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  info.isNoAnswer = ancount > 0 ? 0 : 1;
  info.serverAddr = server_addr;
  info.cname = ares_ans_all_cname(dnsrec);
  ares_set_hquery_process(qtype, hquery, status, info);
}

struct ares_addrinfo *
ares_cached_addrinfo_to_ares_addrinfo(const ares_cached_addrinfo cached_addrinfo[static MAX_RESULTS], uint32_t num) {
  uint32_t real_num = num > MAX_RESULTS ? MAX_RESULTS : num;
  if (num == 0) {
    return NULL;
  }
 
  struct ares_addrinfo_node *head_res = ares_malloc(sizeof(struct ares_addrinfo_node));
  if (head_res == NULL) {
    return NULL;
  }
  memset(head_res, 0, sizeof(struct ares_addrinfo_node));
 
  struct ares_addrinfo_node *now_node = head_res;
  for (uint32_t i = 0; i < real_num; ++i) {
    if (cached_addrinfo[i].ai_addrlen > sizeof(ares_align_sock_addr)) {
      continue;
    }
 
    struct ares_addrinfo_node *next_node = ares_malloc(sizeof(struct ares_addrinfo_node));
    if (next_node == NULL) {
      ares_freeaddrinfo_nodes(head_res);
      return NULL;
    }
    memset(next_node, 0, sizeof(struct ares_addrinfo_node));
    now_node->ai_next = next_node;
    now_node = next_node;
 
    next_node->ai_flags = (int) cached_addrinfo[i].ai_flags;
    next_node->ai_family = (int) cached_addrinfo[i].ai_family;
    next_node->ai_socktype = (int) cached_addrinfo[i].ai_socktype;
    next_node->ai_protocol = (int) cached_addrinfo[i].ai_protocol;
    next_node->ai_addrlen = (ares_socklen_t) cached_addrinfo[i].ai_addrlen;
    next_node->ai_addr = ares_malloc(sizeof(ares_align_sock_addr));
    if (next_node->ai_addr == NULL) {
      ares_freeaddrinfo_nodes(head_res);
      return NULL;
    }
    memset(next_node->ai_addr, 0, sizeof(ares_align_sock_addr));
    memcpy(next_node->ai_addr, &cached_addrinfo[i].ai_addr, cached_addrinfo[i].ai_addrlen);
  }
  struct ares_addrinfo *info = ares_malloc(sizeof(struct ares_addrinfo));
  if (info == NULL) {
    ares_freeaddrinfo_nodes(head_res);
    return NULL;
  }
  memset(info, 0, sizeof(struct ares_addrinfo));
 
  info->nodes = head_res->ai_next;
  ares_free(head_res);
  return info;
}
 
struct ares_addrinfo *
#ifdef HAS_NETMANAGER_BASE
	ares_get_dns_cache(const char *host, const char *service, const struct ares_addrinfo_hints *hints, int32_t netId) {
#else
	ares_get_dns_cache(const char *host, const char *service, const struct ares_addrinfo_hints *hints) {
#endif
  param.host = (char *) host;
  param.serv = (char *) service;
  struct addrinfo hint = {0};
  ares_addrinfo_hints_to_addrinfo(hints, &hint);
  param.hint = &hint;
 
  ares_cached_addrinfo cached_addrinfo[MAX_RESULTS] = {0};
  memset(cached_addrinfo, 0, sizeof(ares_cached_addrinfo) * MAX_RESULTS);
  uint32_t num = 0;
  if (num == 0) {
    return NULL;
  }
  return ares_cached_addrinfo_to_ares_addrinfo(cached_addrinfo, num);
}
 
void ares_set_dns_cache(const char *host, const char *service, const struct ares_addrinfo_hints *hints,
#ifdef HAS_NETMANAGER_BASE
                        const struct ares_addrinfo *res, int32_t netId) {
#else
                        const struct ares_addrinfo *res) {
#endif
  ares_cache_key_param_wrapper param = {0};
  param.host = (char *) host;
  param.serv = (char *) service;
  struct addrinfo hint = {0};
  ares_addrinfo_hints_to_addrinfo(hints, &hint);
  param.hint = &hint;
 
  struct addrinfo *posix_res = ares_addrinfo_to_addrinfo(res);
  if (!posix_res) {
    return;
  }
  ares_free_posix_addrinfo(posix_res);
}
#endif

struct ares_addrinfo_cname *
  ares_append_addrinfo_cname(struct ares_addrinfo_cname **head)
{
  struct ares_addrinfo_cname *tail = ares_malloc_zero(sizeof(*tail));
  struct ares_addrinfo_cname *last = *head;

  if (tail == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!last) {
    *head = tail;
    return tail;
  }

  while (last->next) {
    last = last->next;
  }

  last->next = tail;
  return tail;
}

void ares_addrinfo_cat_cnames(struct ares_addrinfo_cname **head,
                              struct ares_addrinfo_cname  *tail)
{
  struct ares_addrinfo_cname *last = *head;
  if (!last) {
    *head = tail;
    return;
  }

  while (last->next) {
    last = last->next;
  }

  last->next = tail;
}

/* Allocate new addrinfo and append to the tail. */
struct ares_addrinfo_node *
  ares_append_addrinfo_node(struct ares_addrinfo_node **head)
{
  struct ares_addrinfo_node *tail = ares_malloc_zero(sizeof(*tail));
  struct ares_addrinfo_node *last = *head;

  if (tail == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!last) {
    *head = tail;
    return tail;
  }

  while (last->ai_next) {
    last = last->ai_next;
  }

  last->ai_next = tail;
  return tail;
}

void ares_addrinfo_cat_nodes(struct ares_addrinfo_node **head,
                             struct ares_addrinfo_node  *tail)
{
  struct ares_addrinfo_node *last = *head;
  if (!last) {
    *head = tail;
    return;
  }

  while (last->ai_next) {
    last = last->ai_next;
  }

  last->ai_next = tail;
}

/* Resolve service name into port number given in host byte order.
 * If not resolved, return 0.
 */
static unsigned short lookup_service(const char *service, int flags)
{
  const char     *proto;
  struct servent *sep;
#ifdef HAVE_GETSERVBYNAME_R
  struct servent se;
  char           tmpbuf[4096];
#endif

  if (service) {
    if (flags & ARES_NI_UDP) {
      proto = "udp";
    } else if (flags & ARES_NI_SCTP) {
      proto = "sctp";
    } else if (flags & ARES_NI_DCCP) {
      proto = "dccp";
    } else {
      proto = "tcp";
    }
#ifdef HAVE_GETSERVBYNAME_R
    memset(&se, 0, sizeof(se));
    sep = &se;
    memset(tmpbuf, 0, sizeof(tmpbuf));
#  if GETSERVBYNAME_R_ARGS == 6
    if (getservbyname_r(service, proto, &se, (void *)tmpbuf, sizeof(tmpbuf),
                        &sep) != 0) {
      sep = NULL; /* LCOV_EXCL_LINE: buffer large so this never fails */
    }
#  elif GETSERVBYNAME_R_ARGS == 5
    sep = getservbyname_r(service, proto, &se, (void *)tmpbuf, sizeof(tmpbuf));
#  elif GETSERVBYNAME_R_ARGS == 4
    if (getservbyname_r(service, proto, &se, (void *)tmpbuf) != 0) {
      sep = NULL;
    }
#  else
    /* Lets just hope the OS uses TLS! */
    sep = getservbyname(service, proto);
#  endif
#else
    /* Lets just hope the OS uses TLS! */
#  if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
    sep = getservbyname(service, (char *)proto);
#  else
    sep = getservbyname(service, proto);
#  endif
#endif
    return (sep ? ntohs((unsigned short)sep->s_port) : 0);
  }
  return 0;
}

/* If the name looks like an IP address or an error occurred,
 * fake up a host entry, end the query immediately, and return true.
 * Otherwise return false.
 */
static ares_bool_t fake_addrinfo(const char *name, unsigned short port,
                                 const struct ares_addrinfo_hints *hints,
                                 struct ares_addrinfo             *ai,
                                 ares_addrinfo_callback callback, void *arg)
{
  struct ares_addrinfo_cname *cname;
  ares_status_t               status = ARES_SUCCESS;
  ares_bool_t                 result = ARES_FALSE;
  int                         family = hints->ai_family;
  if (family == AF_INET || family == AF_INET6 || family == AF_UNSPEC) {
    /* It only looks like an IP address if it's all numbers and dots. */
    size_t      numdots = 0;
    ares_bool_t valid   = ARES_TRUE;
    const char *p;
    for (p = name; *p; p++) {
      if (!ares_isdigit(*p) && *p != '.') {
        valid = ARES_FALSE;
        break;
      } else if (*p == '.') {
        numdots++;
      }
    }

    /* if we don't have 3 dots, it is illegal
     * (although inet_pton doesn't think so).
     */
    if (numdots != 3 || !valid) {
      result = ARES_FALSE;
    } else {
      struct in_addr addr4;
      result =
        ares_inet_pton(AF_INET, name, &addr4) < 1 ? ARES_FALSE : ARES_TRUE;
      if (result) {
        status = ares_append_ai_node(AF_INET, port, 0, &addr4, &ai->nodes);
        if (status != ARES_SUCCESS) {
          callback(arg, (int)status, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
          return ARES_TRUE;                    /* LCOV_EXCL_LINE: OutOfMemory */
        }
      }
    }
  }

  if (!result && (family == AF_INET6 || family == AF_UNSPEC)) {
    struct ares_in6_addr addr6;
    result =
      ares_inet_pton(AF_INET6, name, &addr6) < 1 ? ARES_FALSE : ARES_TRUE;
    if (result) {
      status = ares_append_ai_node(AF_INET6, port, 0, &addr6, &ai->nodes);
      if (status != ARES_SUCCESS) {
        callback(arg, (int)status, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
        return ARES_TRUE;                    /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  if (!result) {
    return ARES_FALSE;
  }

  if (hints->ai_flags & ARES_AI_CANONNAME) {
    cname = ares_append_addrinfo_cname(&ai->cnames);
    if (!cname) {
      /* LCOV_EXCL_START: OutOfMemory */
      ares_freeaddrinfo(ai);
      callback(arg, ARES_ENOMEM, 0, NULL);
      return ARES_TRUE;
      /* LCOV_EXCL_STOP */
    }

    /* Duplicate the name, to avoid a constness violation. */
    cname->name = ares_strdup(name);
    if (!cname->name) {
      ares_freeaddrinfo(ai);
      callback(arg, ARES_ENOMEM, 0, NULL);
      return ARES_TRUE;
    }
  }

  ai->nodes->ai_socktype = hints->ai_socktype;
  ai->nodes->ai_protocol = hints->ai_protocol;

  callback(arg, ARES_SUCCESS, 0, ai);
  return ARES_TRUE;
}

static void hquery_free(struct host_query *hquery, ares_bool_t cleanup_ai)
{
  if (cleanup_ai) {
    ares_freeaddrinfo(hquery->ai);
  }
  ares_strsplit_free(hquery->names, hquery->names_cnt);
  ares_free(hquery->name);
  ares_free(hquery->lookups);
#if OHOS_DNS_PROXY_BY_NETSYS
  ares_free(hquery->src_addr);
  free_process_info(hquery->process_info);
  ares_freeaddrinfo_nodes(hquery->ipv4LocalAddrAi);
#endif
  ares_free(hquery);
}

static void end_hquery(struct host_query *hquery, ares_status_t status)
{
  struct ares_addrinfo_node  sentinel;
  struct ares_addrinfo_node *next;

  if (status == ARES_SUCCESS) {
    if (!(hquery->hints.ai_flags & ARES_AI_NOSORT) && hquery->ai->nodes) {
      sentinel.ai_next = hquery->ai->nodes;
      ares_sortaddrinfo(hquery->channel, &sentinel);
      hquery->ai->nodes = sentinel.ai_next;
    }
    next = hquery->ai->nodes;

    while (next) {
      next->ai_socktype = hquery->hints.ai_socktype;
      next->ai_protocol = hquery->hints.ai_protocol;
      next              = next->ai_next;
    }
  } else {
    /* Clean up what we have collected by so far. */
    ares_freeaddrinfo(hquery->ai);
    hquery->ai = NULL;
  }
#if OHOS_DNS_PROXY_BY_NETSYS
  char serv[12] = {0};
  sprintf(serv, "%d", hquery->port);
#ifdef HAS_NETMANAGER_BASE
  ares_set_dns_cache(hquery->name, serv, &hquery->hints, hquery->ai, hquery->channel->netId);
#else
  ares_set_dns_cache(hquery->name, serv, &hquery->hints, hquery->ai);
#endif
  hquery->process_info.hostname = hquery->name;
  hquery->process_info.retCode = status;
  int allDuration = ares_get_now_time() - hquery->process_info.queryTime;
  int firstQueryEnd2AppDuration = allDuration - hquery->process_info.firstQueryEndDuration;
  hquery->process_info.firstQueryEnd2AppDuration = firstQueryEnd2AppDuration;
  ares_record_process(status, hquery->name, hquery->process_info.queryTime, NULL, hquery);
#endif
  hquery->callback(hquery->arg, (int)status, (int)hquery->timeouts, hquery->ai);
  hquery_free(hquery, ARES_FALSE);
}

ares_bool_t ares_is_localhost(const char *name)
{
  /* RFC6761 6.3 says : The domain "localhost." and any names falling within
   * ".localhost." */
  size_t len;

  if (name == NULL) {
    return ARES_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (ares_strcaseeq(name, "localhost")) {
    return ARES_TRUE;
  }

  len = ares_strlen(name);
  if (len < 10 /* strlen(".localhost") */) {
    return ARES_FALSE;
  }

  if (ares_strcaseeq(name + (len - 10 /* strlen(".localhost") */),
                     ".localhost")) {
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

static ares_status_t file_lookup(struct host_query *hquery)
{
  const ares_hosts_entry_t *entry;
  ares_status_t             status;

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN. */
  if (ares_is_onion_domain(hquery->name)) {
    return ARES_ENOTFOUND;
  }

  status = ares_hosts_search_host(
    hquery->channel,
    (hquery->hints.ai_flags & ARES_AI_ENVHOSTS) ? ARES_TRUE : ARES_FALSE,
    hquery->name, &entry);

  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_hosts_entry_to_addrinfo(
    entry, hquery->name, hquery->hints.ai_family, hquery->port,
    (hquery->hints.ai_flags & ARES_AI_CANONNAME) ? ARES_TRUE : ARES_FALSE,
    hquery->ai);

  if (status != ARES_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }


done:
  /* RFC6761 section 6.3 #3 states that "Name resolution APIs and libraries
   * SHOULD recognize localhost names as special and SHOULD always return the
   * IP loopback address for address queries".
   * We will also ignore ALL errors when trying to resolve localhost, such
   * as permissions errors reading /etc/hosts or a malformed /etc/hosts.
   *
   * Also, just because the query itself returned success from /etc/hosts
   * lookup doesn't mean it returned everything it needed to for all requested
   * address families. As long as we're not on a critical out of memory
   * condition pass it through to fill in any other address classes. */
  if (status != ARES_ENOMEM && ares_is_localhost(hquery->name)) {
    return ares_addrinfo_localhost(hquery->name, hquery->port, &hquery->hints,
                                   hquery->ai);
  }

  return status;
}

static void next_lookup(struct host_query *hquery, ares_status_t status)
{
  switch (*hquery->remaining_lookups) {
    case 'b':
      /* RFC6761 section 6.3 #3 says "Name resolution APIs SHOULD NOT send
       * queries for localhost names to their configured caching DNS
       * server(s)."
       * Otherwise, DNS lookup. */
      if (!ares_is_localhost(hquery->name) && next_dns_lookup(hquery)) {
        break;
      }

      hquery->remaining_lookups++;
      next_lookup(hquery, status);
      break;

    case 'f':
      /* Host file lookup */
      if (file_lookup(hquery) == ARES_SUCCESS) {
        end_hquery(hquery, ARES_SUCCESS);
        break;
      }
      hquery->remaining_lookups++;
      next_lookup(hquery, status);
      break;
    default:
      /* No lookup left */
      end_hquery(hquery, status);
      break;
  }
}

static void terminate_retries(const struct host_query *hquery,
                              unsigned short           qid)
{
  unsigned short term_qid =
    (qid == hquery->qid_a) ? hquery->qid_aaaa : hquery->qid_a;
  const ares_channel_t *channel = hquery->channel;
  ares_query_t         *query   = NULL;

  /* No other outstanding queries, nothing to do */
  if (!hquery->remaining) {
    return;
  }

  query = ares_htable_szvp_get_direct(channel->queries_by_qid, term_qid);
  if (query == NULL) {
    return;
  }

  query->no_retries = ARES_TRUE;
}

static ares_bool_t ai_has_ipv4(struct ares_addrinfo *ai)
{
  struct ares_addrinfo_node *node;

  for (node = ai->nodes; node != NULL; node = node->ai_next) {
    if (node->ai_family == AF_INET) {
      return ARES_TRUE;
    }
  }
  return ARES_FALSE;
}

#if OHOS_DNS_PROXY_BY_NETSYS
static void ares_addrinfo_cat_local_addr(struct host_query *hquery)
{
  if (hquery->ipv4LocalAddrAi && !ai_has_ipv4(hquery->ai)) {
    ares_addrinfo_cat_nodes(&hquery->ai->nodes, hquery->ipv4LocalAddrAi);
    hquery->ipv4LocalAddrAi = NULL;
  }
}
#endif

static void host_callback(void *arg, ares_status_t status, size_t timeouts,
                          const ares_dns_record_t *dnsrec)
{
  struct host_query *hquery         = (struct host_query *)arg;
  ares_status_t      addinfostatus  = ARES_SUCCESS;
  hquery->timeouts                 += timeouts;
  hquery->remaining--;

  if (status == ARES_SUCCESS) {
    if (dnsrec == NULL) {
      addinfostatus = ARES_EBADRESP; /* LCOV_EXCL_LINE: DefensiveCoding */
    } else {
#if OHOS_DNS_PROXY_BY_NETSYS
      addinfostatus =
        ares_parse_into_addrinfo(dnsrec, ARES_TRUE, hquery->port, hquery->ai, &hquery->ipv4LocalAddrAi);
#else
       addinfostatus =
        ares_parse_into_addrinfo(dnsrec, ARES_TRUE, hquery->port, hquery->ai);
#endif
    }

    /* We sent out ipv4 and ipv6 requests simultaneously.  If we got a
     * successful ipv4 response, we want to go ahead and tell the ipv6 request
     * that if it fails or times out to not try again since we have the data
     * we need.
     *
     * Our initial implementation of this would terminate retries if we got any
     * successful response (ipv4 _or_ ipv6).  But we did get some user-reported
     * issues with this that had bad system configs and odd behavior:
     *  https://github.com/alpinelinux/docker-alpine/issues/366
     *
     * Essentially the ipv6 query succeeded but the ipv4 query failed or timed
     * out, and so we only returned the ipv6 address, but the host couldn't
     * use ipv6.  If we continued to allow ipv4 retries it would have found a
     * server that worked and returned both address classes (this is clearly
     * unexpected behavior).
     *
     * At some point down the road if ipv6 actually becomes required and
     * reliable we can drop this ipv4 check.
     */
    if (addinfostatus == ARES_SUCCESS && ai_has_ipv4(hquery->ai)) {
      terminate_retries(hquery, ares_dns_record_get_id(dnsrec));
    }
  }
#if OHOS_DNS_PROXY_BY_NETSYS
  ares_parse_query_info(status, dnsrec, hquery);
#endif
  if (!hquery->remaining) {
    if (status == ARES_EDESTRUCTION || status == ARES_ECANCELLED) {
      /* must make sure we don't do next_lookup() on destroy or cancel,
       * and return the appropriate status.  We won't return a partial
       * result in this case. */
      end_hquery(hquery, status);
    } else if (addinfostatus != ARES_SUCCESS && addinfostatus != ARES_ENODATA) {
      /* error in parsing result e.g. no memory */
      if (addinfostatus == ARES_EBADRESP && hquery->ai->nodes) {
        /* We got a bad response from server, but at least one query
         * ended with ARES_SUCCESS */
        end_hquery(hquery, ARES_SUCCESS);
      } else {
        end_hquery(hquery, addinfostatus);
      }
    } else if (hquery->ai->nodes) {
#if OHOS_DNS_PROXY_BY_NETSYS
      ares_addrinfo_cat_local_addr(hquery);
#endif
      /* at least one query ended with ARES_SUCCESS */
      end_hquery(hquery, ARES_SUCCESS);
    } else if (status == ARES_ENOTFOUND || status == ARES_ENODATA ||
               addinfostatus == ARES_ENODATA) {
      if (status == ARES_ENODATA || addinfostatus == ARES_ENODATA) {
        hquery->nodata_cnt++;
      }
#if OHOS_DNS_PROXY_BY_NETSYS
      if (hquery->nodata_cnt < ares_slist_len(hquery->channel->servers) && hquery->nodata_cnt > 0) {
        hquery->next_name_idx--;
        ares_slist_node_t *node;
        ares_server_t *server;
        server = ares_slist_node_val(ares_slist_node_first(hquery->channel->servers));
        server->consec_failures++;
        node = ares_slist_node_find(hquery->channel->servers, server);
        ares_slist_node_reinsert(node);
        ares_qcache_flush(hquery->channel->qcache);
      }
      if (hquery->nodata_cnt >= ares_slist_len(hquery->channel->servers) && hquery->nodata_cnt > 0) {
        ares_addrinfo_cat_local_addr(hquery);
        end_hquery(hquery, ARES_SUCCESS);
        return;
      }
#endif
      next_lookup(hquery, hquery->nodata_cnt ? ARES_ENODATA : status);
    } else if ((status == ARES_ESERVFAIL || status == ARES_EREFUSED) &&
               ares_name_label_cnt(hquery->names[hquery->next_name_idx - 1]) ==
                 1) {
      /* Issue #852, systemd-resolved may return SERVFAIL or REFUSED on a
       * single label domain name. */
      next_lookup(hquery, hquery->nodata_cnt ? ARES_ENODATA : status);
    } else {
      end_hquery(hquery, status);
    }
  }

  /* at this point we keep on waiting for the next query to finish */
}

static void ares_getaddrinfo_int(ares_channel_t *channel, const char *name,
                                 const char                       *service,
                                 const struct ares_addrinfo_hints *hints,
                                 ares_addrinfo_callback callback, void *arg)
{
#if OHOS_DNS_PROXY_BY_NETSYS
  long long time_now = ares_get_now_time();
#ifdef HAS_NETMANAGER_BASE
  struct ares_addrinfo *cache_res = ares_get_dns_cache(name, service, hints, channel->netId);
#else
  struct ares_addrinfo *cache_res = ares_get_dns_cache(name, service, hints);
#endif
  if (cache_res && cache_res->nodes) {
    ares_record_process(ARES_SUCCESS, name, time_now, cache_res, NULL);
    callback(arg, ARES_SUCCESS, 0, cache_res);
    return;
  }
#endif
  struct host_query    *hquery;
  unsigned short        port = 0;
  int                   family;
  struct ares_addrinfo *ai;
  ares_status_t         status;

  if (!hints) {
    hints = &default_hints;
  }

  family = hints->ai_family;

  /* Right now we only know how to look up Internet addresses
     and unspec means try both basically. */
  if (family != AF_INET && family != AF_INET6 && family != AF_UNSPEC) {
    callback(arg, ARES_ENOTIMP, 0, NULL);
    return;
  }

  if (ares_is_onion_domain(name)) {
    callback(arg, ARES_ENOTFOUND, 0, NULL);
    return;
  }

  if (service) {
    if (hints->ai_flags & ARES_AI_NUMERICSERV) {
      unsigned long val;
      errno = 0;
      val   = strtoul(service, NULL, 0);
      if ((val == 0 && errno != 0) || val > 65535) {
        callback(arg, ARES_ESERVICE, 0, NULL);
        return;
      }
      port = (unsigned short)val;
    } else {
      port = lookup_service(service, 0);
      if (!port) {
        unsigned long val;
        errno = 0;
        val   = strtoul(service, NULL, 0);
        if ((val == 0 && errno != 0) || val > 65535) {
          callback(arg, ARES_ESERVICE, 0, NULL);
          return;
        }
        port = (unsigned short)val;
      }
    }
  }

  ai = ares_malloc_zero(sizeof(*ai));
  if (!ai) {
    callback(arg, ARES_ENOMEM, 0, NULL);
    return;
  }

  if (fake_addrinfo(name, port, hints, ai, callback, arg)) {
    return;
  }

  /* Allocate and fill in the host query structure. */
  hquery = ares_malloc_zero(sizeof(*hquery));
  if (!hquery) {
    ares_freeaddrinfo(ai);
    callback(arg, ARES_ENOMEM, 0, NULL);
    return;
  }

  hquery->port        = port;
  hquery->channel     = channel;
  hquery->hints       = *hints;
  hquery->sent_family = -1; /* nothing is sent yet */
  hquery->callback    = callback;
  hquery->arg         = arg;
  hquery->ai          = ai;
  hquery->name        = ares_strdup(name);
#if OHOS_DNS_PROXY_BY_NETSYS
  hquery->src_addr    = NULL;
  hquery->process_info.queryTime = time_now;
  hquery->process_info.retCode = ARES_ENODATA;
  hquery->process_info.firstQueryEndDuration = 0;
  hquery->process_info.firstQueryEnd2AppDuration = 0;
  hquery->process_info.firstReturnType = 0;
  hquery->process_info.sourceFrom = SOURCE_FROM_CARES;
  hquery->process_info.ipv4QueryInfo = empty_family_query_info;
  hquery->process_info.ipv6QueryInfo = empty_family_query_info;
#endif
  if (hquery->name == NULL) {
#if OHOS_DNS_PROXY_BY_NETSYS
    ares_record_process(ARES_ENOMEM, name, time_now, NULL, NULL);
#endif
    hquery_free(hquery, ARES_TRUE);
    callback(arg, ARES_ENOMEM, 0, NULL);
    return;
  }

  status =
    ares_search_name_list(channel, name, &hquery->names, &hquery->names_cnt);
  if (status != ARES_SUCCESS) {
#if OHOS_DNS_PROXY_BY_NETSYS
    ares_record_process(status, name, time_now, NULL, NULL);
#endif
    hquery_free(hquery, ARES_TRUE);
    callback(arg, (int)status, 0, NULL);
    return;
  }
  hquery->next_name_idx = 0;


  hquery->lookups = ares_strdup(channel->lookups);
  if (hquery->lookups == NULL) {
#if OHOS_DNS_PROXY_BY_NETSYS
    ares_record_process(status, name, time_now, NULL, NULL);
#endif
    hquery_free(hquery, ARES_TRUE);
    callback(arg, ARES_ENOMEM, 0, NULL);
    return;
  }
  hquery->remaining_lookups = hquery->lookups;

  /* Start performing lookups according to channel->lookups. */
  next_lookup(hquery, ARES_ECONNREFUSED /* initial error code */);
}

void ares_getaddrinfo(ares_channel_t *channel, const char *name,
                      const char                       *service,
                      const struct ares_addrinfo_hints *hints,
                      ares_addrinfo_callback callback, void *arg)
{
  if (channel == NULL) {
    return;
  }
  ares_channel_lock(channel);
  ares_getaddrinfo_int(channel, name, service, hints, callback, arg);
  ares_channel_unlock(channel);
}

static ares_bool_t next_dns_lookup(struct host_query *hquery)
{
  const char *name = NULL;

  if (hquery->next_name_idx >= hquery->names_cnt) {
    return ARES_FALSE;
  }

  name = hquery->names[hquery->next_name_idx++];

  /* NOTE: hquery may be invalidated during the call to ares_query_qid(),
   *       so should not be referenced after this point */
  switch (hquery->hints.ai_family) {
    case AF_INET:
      hquery->remaining += 1;
      ares_query_nolock(hquery->channel, name, ARES_CLASS_IN, ARES_REC_TYPE_A,
                        host_callback, hquery, &hquery->qid_a);
      break;
    case AF_INET6:
      hquery->remaining += 1;
      ares_query_nolock(hquery->channel, name, ARES_CLASS_IN,
                        ARES_REC_TYPE_AAAA, host_callback, hquery,
                        &hquery->qid_aaaa);
      break;
    case AF_UNSPEC:
      hquery->remaining += 2;
      ares_query_nolock(hquery->channel, name, ARES_CLASS_IN, ARES_REC_TYPE_A,
                        host_callback, hquery, &hquery->qid_a);
      ares_query_nolock(hquery->channel, name, ARES_CLASS_IN,
                        ARES_REC_TYPE_AAAA, host_callback, hquery,
                        &hquery->qid_aaaa);
      break;
    default:
      break;
  }

  return ARES_TRUE;
}
