int
vn_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
    int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* getxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	/*
	 * Non-kernel request need extra checks performed.
	 *
	 * The XATTR_NOSECURITY flag implies a kernel request.
	 */
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_getextattr(context, vp, name, uio);
		if (error) {
			goto out;
		}
#endif /* MAC */
		if ((error = xattr_validatename(name))) {
			goto out;
		}
		if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context))) {
			goto out;
		}
	}

	/* The offset can only be non-zero for resource forks. */
	if (uio_offset(uio) != 0 &&
	    strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_GETXATTR(vp, name, uio, size, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_getxattr(vp, name, uio, size, options, context);
	}
out:
	return error;
}

/*
 * Set the data of an extended attribute.
 */
int
vn_setxattr(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* setxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	if ((options & (XATTR_REPLACE | XATTR_CREATE)) == (XATTR_REPLACE | XATTR_CREATE)) {
		return EINVAL;
	}
	if ((error = xattr_validatename(name))) {
		return error;
	}
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_setextattr(context, vp, name, uio);
		if (error) {
			goto out;
		}
#endif /* MAC */
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context);
		if (error) {
			goto out;
		}
	}
	/* The offset can only be non-zero for resource forks. */
	if (uio_offset(uio) != 0 &&
	    strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_SETXATTR(vp, name, uio, options, context);
#ifdef DUAL_EAS
	/*
	 * An EJUSTRETURN is from a filesystem which keeps this xattr
	 * natively as well as in a dot-underscore file.  In this case the
	 * EJUSTRETURN means the filesytem has done nothing, but identifies the
	 * EA as one which may be represented natively and/or in a DU, and
	 * since XATTR_CREATE or XATTR_REPLACE was specified, only up here in
	 * in vn_setxattr can we do the getxattrs needed to ascertain whether
	 * the XATTR_{CREATE,REPLACE} should yield an error.
	 */
	if (error == EJUSTRETURN) {
		int native = 0, dufile = 0;
		size_t sz;      /* not used */

		native = VNOP_GETXATTR(vp, name, NULL, &sz, 0, context) ? 0 : 1;
		dufile = default_getxattr(vp, name, NULL, &sz, 0, context) ? 0 : 1;
		if (options & XATTR_CREATE && (native || dufile)) {
			error = EEXIST;
			goto out;
		}
		if (options & XATTR_REPLACE && !(native || dufile)) {
			error = ENOATTR;
			goto out;
		}
		/*
		 * Having determined no CREATE/REPLACE error should result, we
		 * zero those bits, so both backing stores get written to.
		 */
		options &= ~(XATTR_CREATE | XATTR_REPLACE);
		error = VNOP_SETXATTR(vp, name, uio, options, context);
		/* the mainline path here is to have error==ENOTSUP ... */
	}
#endif /* DUAL_EAS */
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_setxattr(vp, name, uio, options, context);
	}
#if CONFIG_MACF
	if ((error == 0) && !(options & XATTR_NOSECURITY)) {
		mac_vnode_notify_setextattr(context, vp, name, uio);
		if (vfs_flags(vnode_mount(vp)) & MNT_MULTILABEL) {
			mac_vnode_label_update_extattr(vnode_mount(vp), vp, name);
		}
	}
#endif
out:
	return error;
}

/*
 * Remove an extended attribute.
 */
int
vn_removexattr(vnode_t vp, const char * name, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* removexattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	if ((error = xattr_validatename(name))) {
		return error;
	}
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_deleteextattr(context, vp, name);
		if (error) {
			goto out;
		}
#endif /* MAC */
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context);
		if (error) {
			goto out;
		}
	}
	error = VNOP_REMOVEXATTR(vp, name, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_removexattr(vp, name, options, context);
#ifdef DUAL_EAS
	} else if (error == EJUSTRETURN) {
		/*
		 * EJUSTRETURN is from a filesystem which keeps this xattr natively as well
		 * as in a dot-underscore file.  EJUSTRETURN means the filesytem did remove
		 * a native xattr, so failure to find it in a DU file during
		 * default_removexattr should not be considered an error.
		 */
		error = default_removexattr(vp, name, options, context);
		if (error == ENOATTR) {
			error = 0;
		}
#endif /* DUAL_EAS */
	}
#if CONFIG_MACF
	if ((error == 0) && !(options & XATTR_NOSECURITY)) {
		mac_vnode_notify_deleteextattr(context, vp, name);
		if (vfs_flags(vnode_mount(vp)) & MNT_MULTILABEL) {
			mac_vnode_label_update_extattr(vnode_mount(vp), vp, name);
		}
	}
#endif
out:
	return error;
}

/*
 * Retrieve the list of extended attribute names.
 */
int
vn_listxattr(vnode_t vp, uio_t uio, size_t *size, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* listxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		return EPERM;
	}
#endif

	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_listextattr(context, vp);
		if (error) {
			goto out;
		}
#endif /* MAC */

		error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context);
		if (error) {
			goto out;
		}
	}

	error = VNOP_LISTXATTR(vp, uio, size, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some but not all EAs natively, in which case
		 * the native EA names will have been uiomove-d out (or *size updated)
		 * and the default_listxattr here will finish the job.
		 */
		error = default_listxattr(vp, uio, size, options, context);
	}
out:
	return error;
}
