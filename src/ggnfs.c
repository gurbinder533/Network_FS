/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall hello.c `pkg-config fuse --cflags --libs` -o hello
*/

#define FUSE_USE_VERSION 26

#include <limits.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

/* libssh files */
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <stdlib.h>



struct ggnfs_state {
    ssh_session session;
    sftp_session sftp;
    char *rootdir;
    char *remoteHost;

};


static struct ggnfs_state ggnfs_data;

#define GGNFS_DATA ((struct ggnfs_state *) fuse_get_context()->private_data)

static const char *hello_str = "Hello World!\n";
static const char *hello_path = "/hello";

static const char *remotePath = "/h1/ggill/Gill/AOS/lab2/fs";
static const char *tmp_dir = "/home/gill/AOS/labs/lab2/tmp_dir";

/* libssh stuff */
int verify_knownhost(ssh_session session)
{
    int state, hlen;
    unsigned char *hash = NULL;
    char *hexa;
    char buf[10];
    state = ssh_is_server_known(session);
    hlen = ssh_get_pubkey_hash(session, &hash);
    if (hlen < 0)
        return -1;
        switch (state)
        {
            case SSH_SERVER_KNOWN_OK:
            break; /* ok */
            case SSH_SERVER_KNOWN_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            free(hash);
            return -1;
            case SSH_SERVER_FOUND_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
            "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
            "confuse your client into thinking the key does not exist\n");
            free(hash);
            return -1;
            case SSH_SERVER_FILE_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
            "automatically created.\n");
            /* fallback to SSH_SERVER_NOT_KNOWN behavior */
            case SSH_SERVER_NOT_KNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            free(hexa);
            if (fgets(buf, sizeof(buf), stdin) == NULL)
            {
                free(hash);
                return -1;
            }
            if (strncasecmp(buf, "yes", 3) != 0)
            {
                free(hash);
                return -1;
            }
            if (ssh_write_knownhost(session) < 0)
            {
                fprintf(stderr, "Error %s\n", strerror(errno));
                free(hash);
                return -1;
            }
            break;
            case SSH_SERVER_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            free(hash);
            return -1;
        }
        free(hash);
        return 0;
}

/**
 * Reading remote file
 * source: libssh.org Tutorial
 */

int scp_receive(ssh_session session, ssh_scp scp)
{
    int rc;
    int size, mode;
    char *filename, *buffer;
    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_NEWFILE)
    {
        fprintf(stderr, "Error receiving information about file: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    size = ssh_scp_request_get_size(scp);
    filename = strdup(ssh_scp_request_get_filename(scp));
    mode = ssh_scp_request_get_permissions(scp);
    printf("Receiving file %s, size %d, permisssions 0%o\n",
    filename, size, mode);
    free(filename);
    buffer = malloc(size);
    if (buffer == NULL)
    {
        fprintf(stderr, "Memory allocation error\n");
        return SSH_ERROR;
    }
    ssh_scp_accept_request(scp);
    rc = ssh_scp_read(scp, buffer, size);
    if (rc == SSH_ERROR)
    {
        fprintf(stderr, "Error receiving file data: %s\n",
        ssh_get_error(session));
        free(buffer);
        return rc;
    }
    printf("Done\n");
    write(1, buffer, size);
    free(buffer);
    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_EOF)
    {
        fprintf(stderr, "Unexpected request: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    return SSH_OK;
}

int scp_read(ssh_session session, char* fileName)
{
    ssh_scp scp;
    int rc;
    scp = ssh_scp_new
    (session, SSH_SCP_READ, fileName);
    if (scp == NULL)
    {
        fprintf(stderr, "Error allocating scp session: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing scp session: %s\n",
        ssh_get_error(session));
        ssh_scp_free(scp);
        return rc;
    }
    
    scp_receive(session, scp);

    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;
}

/*
static void ggnfs_fullpath(char fpath[PATH_MAX], const char *path) 
{
    strcpy(fpath, ggnfs_data.rootdir);
    strncat(fpath, path, PATH_MAX);

}
static void ggnfs_fullRemotepath(char fRemotepath[PATH_MAX], const char *path) 
{
    strcpy(fRemotepath, remotePath);
    strncat(fRemotepath, path, PATH_MAX);

}
*/
static int ggnfs_getattr(const char *path, struct stat *stbuf)
{
 
    int res = 0;
    sftp_dir dir;
    sftp_attributes attributes;
    attributes = sftp_lstat(ggnfs_data.sftp, remotePath); 
    
    if (attributes != NULL) 
    {
        res = 1;
        // setting struct stat
	memset(stbuf, 0, sizeof(struct stat));

        stbuf->st_uid   = attributes->uid; 
        stbuf->st_gid   = attributes->gid;
        stbuf->st_atime = attributes->atime;
        stbuf->st_ctime = attributes->createtime;
        stbuf->st_mtime = attributes->mtime;
        stbuf->st_size  = attributes->size;
        stbuf->st_mode  = attributes->permissions;

        sftp_attributes_free(attributes);
	res = SSH_OK;
     }
    return res;    

}

static int ggnfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
    int res = 0;

    (void) offset;
    (void) fi;	 

    sftp_dir dir;
    sftp_attributes attributes;
    int rc1;
    dir = sftp_opendir(ggnfs_data.sftp, remotePath);
    if (!dir) 
    {
         fprintf(stderr, "inside readdir  Directory not opened\n",ssh_get_error(ggnfs_data.session));
	 return -1;
    }

    while ((attributes = sftp_readdir(ggnfs_data.sftp, dir)) != NULL)
    {
        if(filler(buf, attributes->name, NULL, 0))
        {
            fprintf(stderr, "Error ggnfs_readdir filler: buffer full");
            return -ENOMEM;
        }
    }

    if (!sftp_dir_eof(dir))
    {
        fprintf(stderr, "Can't list directory: %s\n",
            ssh_get_error(ggnfs_data.session));
        sftp_closedir(dir);
        return SSH_ERROR;
    }

    sftp_attributes_free(attributes);
    rc1 = sftp_closedir(dir);
    if (rc1 != SSH_OK)
    {
         fprintf(stderr, " inside Readdir: Canftp_list_dirt close directory\n");
    }
    return EXIT_SUCCESS;
}

int ggnfs_opendir(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    fprintf(stderr, "i m inside opendir path: %s\n",path );	
    sftp_session sftp;
    int rc;

    sftp = sftp_new(ggnfs_data.session);
    if (sftp == NULL)
    {
         fprintf(stderr, "Error allocating SFTP session: %s\n",
         ssh_get_error(ggnfs_data.session));
     //    return SSH_ERROR;
     }

    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
         fprintf(stderr, "Error initializing SFTP session: %s.\n",
         sftp_get_error(sftp));
         sftp_free(sftp);
      //   return rc;
    }

    ggnfs_data.sftp = sftp; // store for later use. XXX check 
 
    sftp_dir dir;
    sftp_attributes attributes;
    int rc1;
    dir = sftp_opendir(sftp, remotePath);
    if (!dir) 
    {
         fprintf(stderr, "opendir Directory not opened: %s\n",
         ssh_get_error(ggnfs_data.session));
    }
    
    fi->fh = (intptr_t) dir;
   
    sftp_free(sftp); 
    return retstat;
}

static int ggnfs_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, hello_path) != 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int ggnfs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if(strcmp(path, hello_path) != 0)
		return -ENOENT;

	len = strlen(hello_str);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, hello_str + offset, size);
	} else
		size = 0;

	return size;
}

void *ggnfs_init(struct fuse_conn_info *conn)
{
    return GGNFS_DATA;

}
static struct fuse_operations ggnfs_oper = {
	.getattr	= ggnfs_getattr,
	.readdir	= ggnfs_readdir,
	.open		= ggnfs_open,
	.read		= ggnfs_read,
//	.opendir	= ggnfs_opendir,
//	.init		= ggnfs_init,
};


/**** TESTING ****/
int show_remote_ls(ssh_session session)
{

    printf("inside show_remote_ls\n");
    ssh_channel channel;
    int rc;
    char buffer[256];
    unsigned int nbytes;
    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;
        rc = ssh_channel_open_session(channel);
        if (rc != SSH_OK)
        {
            ssh_channel_free(channel);
            return rc;
        }
        char cmd[100];
        strcpy(cmd,"ls  ");
        strcat(cmd,remotePath);
        printf("cmd = %s\n", cmd);
        rc = ssh_channel_request_exec(channel, cmd);
        if (rc != SSH_OK)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return rc;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        while (nbytes > 0)
        {
            if (write(1, buffer, nbytes) != nbytes)
            {
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return SSH_ERROR;
            }
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        }
        if (nbytes < 0)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_OK;
}





int sftp_list_dir(ssh_session session, sftp_session sftp)
{
  sftp_dir dir;
  sftp_attributes attributes;
  int rc;
  dir = sftp_opendir(sftp, remotePath);
  if (!dir)
  {
    fprintf(stderr, "Directory not opened: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
  printf("Name                       Size Perms    Owner\tGroup\n");
  while ((attributes = sftp_readdir(sftp, dir)) != NULL)
  {
    printf("%-20s %10llu %.8o %s(%d)\t%s(%d)\n",
     attributes->name,
     (long long unsigned int) attributes->size,
     attributes->permissions,
     attributes->owner,
     attributes->uid,
     attributes->group,
     attributes->gid);
     sftp_attributes_free(attributes);
  }
  if (!sftp_dir_eof(dir))
  {
    fprintf(stderr, "Can't list directory: %s\n",
            ssh_get_error(session));
    sftp_closedir(dir);
    return SSH_ERROR;
  }
  rc = sftp_closedir(dir);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't close directory: %s\n",
            ssh_get_error(session));
    return rc;
  }
}










int main(int argc, char *argv[])
{
    int fuse_stat;
    //struct ggnfs_state *ggnfs_data;

   /* ggnfs_data = malloc(sizeof(struct ggnfs_state));
    if (ggnfs_data == NULL) {
        perror("main calloc");
        abort();
    }
   */
    ggnfs_data.remoteHost =argv[1]; //"ggill@faraday.ices.utexas.edu";
    ggnfs_data.rootdir = realpath(argv[2], NULL);
    
    printf("hostname -> %s\n", ggnfs_data.remoteHost);
    printf("rootdir -> %s\n", ggnfs_data.rootdir);
    /* start new ssh session */
    int rc;
    ggnfs_data.session = ssh_new();
    if (ggnfs_data.session == NULL)
        exit(-1);
        
     ssh_options_set(ggnfs_data.session, SSH_OPTIONS_HOST, ggnfs_data.remoteHost);   
     rc = ssh_connect(ggnfs_data.session);
     if (rc != SSH_OK)
        {
            fprintf(stderr, "Error connecting to remoteHost: %s\n",
            ssh_get_error(ggnfs_data.session));
            ssh_free(ggnfs_data.session);
            exit(-1);
        }
        // Verify the server's identity
        // For the source code of verify_knowhost(), check previous example
        if (verify_knownhost(ggnfs_data.session) < 0)
        {
            ssh_disconnect(ggnfs_data.session);
            ssh_free(ggnfs_data.session);
            exit(-1);
        }
        // Authenticate ourselves
        char * password = "5vs2Xg89j#";// getpass("Password: ");
        rc = ssh_userauth_password(ggnfs_data.session, NULL, password);
        //rc = ssh_userauth_publickey_auto(ggnfs_data->session, NULL, NULL);
        if (rc != SSH_AUTH_SUCCESS)
        {
            fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(ggnfs_data.session));
            ssh_disconnect(ggnfs_data.session);
            ssh_free(ggnfs_data.session);
            exit(-1);
        }
     

    /** making sftp session **/
    int rc_sftp;
    ggnfs_data.sftp = sftp_new(ggnfs_data.session);
    if (ggnfs_data.sftp == NULL)
    {
         fprintf(stderr, "Error allocating SFTP session: %s\n",
         ssh_get_error(ggnfs_data.session));
     //    return SSH_ERROR;
     }

    rc_sftp = sftp_init(ggnfs_data.sftp);
    if (rc_sftp != SSH_OK)
    {
         fprintf(stderr, "Error initializing SFTP session: %s.\n",
         sftp_get_error(ggnfs_data.sftp));
         sftp_free(ggnfs_data.sftp);
      //   return rc;
    }

	
    int i = 1;
    for(; i < argc; ++i) {
      argv[i] = argv[i+1];
    }
      argv[argc-1] = NULL;
      argc--;

    /*** TESTING: status working ***/
    //printf("show_remote_ls\n");
    //show_remote_ls(ggnfs_data->session);
    //sftp_list_dir(ggnfs_data.session, ggnfs_data.sftp);


    printf("about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &ggnfs_oper, NULL);
    printf("fuse_main returned %d\n", fuse_stat);

    ssh_disconnect(ggnfs_data.session);
    ssh_free(ggnfs_data.session);
    sftp_free(ggnfs_data.sftp);
    return fuse_stat;

}
