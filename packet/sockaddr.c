#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void *sockaddr_addr_offset(const void *x)
{
	if( x == NULL )
		return NULL;

	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in, sin_addr));
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in6, sin6_addr));
	}

	return NULL;
}

unsigned int sockaddr_addr_size(const void *x)
{
	if( x == NULL )
		return 0;
	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return sizeof(struct in_addr);
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return sizeof(struct in6_addr);
	}
	return 0;
}


unsigned int sockaddr_size(const void *x)
{
	if( x == NULL )
		return 0;
	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return sizeof(struct sockaddr_in);
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return sizeof(struct sockaddr_in6);
	}
	return 0;
}

in_port_t *sockaddr_port_offset(const void *x)
{
	if( x == NULL )
		return NULL;

	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in, sin_port));
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in6, sin6_port));
	}

	return NULL;
}
