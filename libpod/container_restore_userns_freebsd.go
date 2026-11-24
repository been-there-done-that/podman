//go:build !remote

package libpod

// FreeBSD has no user namespaces, so PostConfigureNetNS is never set and these are never reached.

type usernsRestoreGrant struct{}

func (c *Container) grantUsernsRestoreAccess() (*usernsRestoreGrant, error) {
	return &usernsRestoreGrant{}, nil
}

func (g *usernsRestoreGrant) revoke() {}

func (c *Container) setupNetworkAfterRestore() error {
	return nil
}
