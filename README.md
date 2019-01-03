# Intro

Notbit is a minimal client for the [Bitmessage](http://bitmessage.org)
network. It is designed to work as a daemon with no UI. The idea is
that it will store messages in the standard maildir format and accept
new messages via a process like sendmail. That way it can be used with
any compliant mail program such as Evolution or Mutt.

Notbit is a work in progress and currently has some limitations.
It can already send and receive messages to regular addresses but it
doesn't yet support channels or broadcasts.

# Disclaimer

I am not a cryptography expert and I don't know whether Notbit or the
Bitmessage protocol is actually safe for secure communications. I
wouldn't recommend using for anything highly sensitive.

# Dependencies

Notbit requires a modern Unix such as Linux. It also requires
libcrypto with support for elliptic-curve cryptography. Unfortunately
if you are building on Fedora you will need to build libcrypto from
source because they don't ship ECC due to patent concerns.

# Building

First you will need to install the build dependencies for your
system. The main one to install is libopenssl-devel to get
libcrypto. If you are building from the git repo you will also need
the standard autotools such as automake and autoconf.

Now you can run the following commands to build Notbit:

```bash
git clone https://github.com/bpeel/notbit.git
cd notbit
./autogen.sh --prefix=$HOME
make
make install
```

This will install Notbit into your home directory. The executable will
be in `~/bin` which is typically already in your search path.

# Running Notbit

Once notbit is built you can run it by just typing `notbit`. By
default this will output logging messages to stdout. It will
immediately try to connect to the network and start downloading
messages. If instead you want to run notbit in the background you can
type `notbit -d` which will launch it as a daemon. In that case you
can see the logging messages by typing:

```bash
tail -f ~/.local/share/notbit/notbit.log
```

If you want to exit the daemon you can type `killall notbit`. This
will do a graceful shutdown.

# Creating an address

Once Notbit is running you can type `notbit-keygen` to create a new
address. The new address will be printed on the standard out. The
private keys for the address are saved in notbit's config files so you
can immediately start receiving messages to this address. If you want
to spend a bit of extra processing time in order to get a shorter
address you can also pass the `-z` option to notbit-keygen. The
`-l <label>` option can be used to specify a label for the key. There
are also other less useful options which can be seen in the help by
typing `notbit-keygen -h`.

# Importing addresses

If you already have some addresses from the official PyBitmessage
client you can import these directly by copying over the keys.dat.
file. To do this, make sure Notbit is not currently running and then
type:

```bash
cp ~/.config/PyBitmessage/keys.dat ~/.local/share/notbit/
```

# Reading messages

If Notbit receives a message for one of the addresses in keys.dat it
will write it out in maildir format. maildir is a standard format
which can be read by most mail programs such as mutt. By default the
maildir will be `~/.maildir`. You can change this with the `-m`
option.

# Sending messages

You can send messages by running the `notbit-sendmail` command. This
takes a message formatted as
[RFC5322](http://tools.ietf.org/html/rfc5322) mail message on the
standard input. This is the same format as used by sendmail so you can
use notbit-sendmail as a drop-in replacement to send messages from
almost any mail client. The addresses used can not be real email
addresses but instead they must be of the form
`<bitmessage-address>@bitmessage`. For example, you could type the
following to create a new address and use it to send a message to the
echo server to test it:

```bash
echo -e "From: "`notbit-keygen`"@bitmessage\\n"\
"To: BM-orkCbppXWSqPpAxnz6jnfTZ2djb5pJKDb@bitmessage\\n"\
"\\n"\
"Hello from Notbit\\x21" | notbit-sendmail
```

Note that any messages you send must have the content type set to
`text/plain` and can't contain any attachments. This means that HTML
messages won't work. They must use either the us-ascii encoding or
UTF-8.

# Integrating with a mail client

Notbit can be used with any mail client that supports maildir and
local delivery via sendmail. For example, to configure an account with
Evolution you would do the following:

* Click the ‘New’ → ‘Mail account’ menu
* In the email address field, type an address generated using
  notbit-keygen. Don't forget to add ‘@bitmessage’ on the end to make
  it look like an email address.
* For the ‘server type’ select ‘Maildir-format mail directories’
* Select the `.maildir` folder as the ‘Mail Directory’. Note that you
  may have to right-click and select ‘show hidden files’ in order to
  see this. Alternatively you can make Notbit use a different
  directory by passing the -m option when you run it.
* Under the ‘Sending E-mail’ settings, select ‘Sendmail’ as the server
  type.
* Tick the ‘Use custom binary’ option and type
  `/home/<you>/bin/notbit-sendmail` as the binary, where <you> is your
  username.
* The rest of the settings can be left at the default.

You should now be able to send a Bitmessage using Evolution. Just
remember to add ‘@bitmessage’ to any address you send to and make sure
you select ‘Plain text’ as the format (HTML emails and attachments
aren't supported by Bitmessage). Don't worry if your name appears in
the From box next to your address as this information won't be sent
over Bitmessage. Only the subject and the body of the mail are sent.

# Using with Tor

You can tell Notbit to connect via a Tor server running on the local
machine by passing the -T option. This will also disable the DNS
bootstrapping and won't open any listening ports. The -T option is a
convienence option which is equivalent to `-r 127.0.0.1:9050 -B -i`.
The -B option disables DNS bootstrapping and the -i argument disables
listening ports. If you are running the Tor server on a different
address you can specify these three options explicitly using the
correct address.

# Options

Notbit has some command line options to configure it. These are listed
below:

```
 -h                    Show a help message
 -p <port>             Specifies a port to listen on.
                       Equivalent to -a [::]:port.
 -a <address[:port]>   Add an address to listen on. Can be
                       specified multiple times. Defaults to
                       [::] to listen on port 8444
 -P <address[:port]>   Add to the list of initial peers that
                       might be connected to.
 -e                    Only connect to peers specified by -P
 -l <file>             Specify the pathname for the log file
                       Defaults to stdout or
                       $XDG_DATA_HOME/notbit/notbit.log if -d is used
 -d                    Fork and detach from terminal after
                       creating listen socket. (Daemonize)
 -T                    Use a local Tor server. Equivalent to
                       -r 127.0.0.1:9050 -B -i
 -r <address[:port]>   Specify a SOCKSv5 proxy to use for
                       outgoing connections.
 -u <user>             Specify a user to run as. Used to drop
                       privileges.
 -g <group>            Specify a group to run as.
 -D <datadir>          Specify an alternate location for the
                       object store. Defaults to $XDG_DATA_HOME/notbit
 -m <maildir>          Specify the maildir to save messages to.
                       Defaults to $HOME/.maildir
 -L                    Allow private addresses for peers
 -b                    Don't bootstrap with default peers.
                       Useful for creating your own private
                       network. Note that this requires all
                       nodes to be trustworthy
 -B                    Don't bootstrap with DNS. Useful if
                       running under Tor.
 -i                    Don't listen for incoming connections.
```
