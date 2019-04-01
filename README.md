# VPC IP Configurator (vic)
The VIC tooling provides push-button AWS VPC infrastructure which conforms to configured needs.

### Up to date changes are currently in the 'dev' branch.

This is a work in progress.

# User Quickstart

Are you working on the VIC project?  So far, here's what you need to start using the tooling:

### Prerequisites from existing Ops team admin:

  1. An IAM user in the dev AWS account, in "admin" IAM group
  1. A shell on a "satellite" host (some server which can make API calls to AWS)
    - **or** your own satellite host, must be inet-hardened beyond app stack

**AWS WARNING**: VIC tooling is designed to operate at the root of an AWS account, and it is critical that this new tooling does not conflict with existing AWS accounts.  At every turn, *never* cross tool stacks between AWS enviornments.


*Why work from a satellite host?*  Easy- a fresh computer lets us guarantee isolation of the new VIC tooling, from our existing AWS management stack.  This serves our needs for operational safety, development cleandliness, as well as forcing a true clean slate for this simple implementation of a complex problem.


### From there, it's all you- you must have:

  - An AWS API Key (self-service once you have Console access)
  - 2FA enabled

  - vic tools (you are here)
    - **or**, this software as installable tool package... (TODO)
  - Install dependencies,
    - boto3 installed on your local machine or dev satellite
      - Just boto, that's all.  Things should stay that way for vic dependencies.

### VIC Tool Setup Instructions (dev edition):

  - Wherever you downloaded this repo, you need it's `bin/` in your `PATH`, several ways to do this:
    - `` cd this/repo && export `./bin/devexport` ``
      - This will merely export the correct `PATH` for your existing shell, not for other shells spawned.
    - You can add the `PATH` to `this_software/bin` in your `~/.profile`

*Eventually this tooling will be installable, but that is not of concern until the tooling hits MVP status.*


### Congratulations, you can now run the `vic` tools.

Try,

`$ vic`

A list of subcommands will be provided in the printed help.

Next, to check your AWS access, try:

`$ vic test-aws`

No access?  No problem.  Run the *safe* interactive tool:

`$ vic config-admin`

Then try `$ vic test-aws` again.

Do you have access to a remote host to work from?  If you have configured AWS creds on your laptop, you can forward them via ssh for use by VIC tooling *without writing them to disk and compromising those cridentials*.

### Congratulations, you can now use or hack on the `vic` tools.

Development notes:

  - 'dev' branch is what all PR's shold be made against
  - rebase upstream 'dev' branch constantly as you work!

  - Base tooling must be scrutinized for quality,
    - anything in `./bin`
    - anything in `./lib`

  - User interface tooling can be created fast and loose,
    - anything in `./libexec`
    - any language is appropriate, if your utility exits 0 on success, nonzero on failure.
    - making a new command:
      - drop a program into `./libexec` which begins with `vic-<something>`
      - vic tooling will immediately work with that tool, e.g `vic something`


