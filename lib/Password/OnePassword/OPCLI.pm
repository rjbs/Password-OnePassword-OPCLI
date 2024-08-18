package Password::OnePassword::OPCLI;
# ABSTRACT: get items out of 1Password with the "op" CLI

use v5.36.0;

use Carp ();
use IPC::Run qw(run timeout);
use JSON::MaybeXS qw(decode_json);

=head1 SYNOPSIS

B<Achtung!>  The interface for this library might change a lot.  The author is
still figuring out how to make it make sense.  That's partly because he doesn't
want to think too hard about errors, and partly because the C<op://> URL scheme
used by 1Password isn't really sufficient for his use.  Still, this is roughly
how you can use it:

  my $one_pw = Password::OnePassword::OPCLI->new;

  # Get the string found in one field in your 1Password storage:
  my $string = $one_pw->get_field("op://Private/PAUSE API/credential");

  # Get the complete document for an item, as a hashref:
  my $pw_item = $one_pw->get_item("op://Work/GitHub");

=cut

=method new

  my $one_pw = Password::OnePassword::OPCLI->new;

This is a do-almost-nothing constructor.  It's only here so that methods are
instance methods, not class methods.  Someday, there may be more arguments to
this, but for now, there are not.

=cut

sub new ($class, @rest) {
  Carp::croak("too many arguments given to constructor, which takes none")
    if @rest;

  bless {}, $class;
}

=method get_item

  my $hashref = $one_pw->get_item($locator);

This looks up an item in 1Password, returning a hashref representing the secret
from 1Password.

The C<$locator> should be I<either> a Password::OnePassword::OPCLI::Locator
object or a string that coerced into one, for which see L</LOCATOR STRINGS>.

If the locator specifies a field name, an exception will be raised.

=cut

sub get_item ($self, $locator) {
  unless (ref $locator) {
    $locator = Password::OnePassword::OPCLI::Locator->_from_string($locator);
  }

  if (defined $locator->field) {
    Carp::croak("passed field-level locator to get_item; drop the field part or use get_field");
  }

  my @op_command = (
    qw(op item get),
    (defined $locator->vault ? ('--vault', $locator->vault) : ()),
    ('--format', 'json'),
    $locator->item,
  );

  local $ENV{OP_ACCOUNT} = $locator->account // $ENV{OP_ACCOUNT};
  open(my $proc, '-|', @op_command) or Carp::croak("can't spawn op: $!");

  my $json = join q{}, <$proc>;

  # TODO: Log $? and $!, do something better. -- rjbs, 2024-05-03
  close($proc) or Carp::croak("problem running 'op item get'");

  return decode_json($json);
}

=method get_field

  my $str = $one_pw->get_field($locator);

This looks up an item in 1Password, using the C<op read> command.

The C<$locator> should be I<either> a Password::OnePassword::OPCLI::Locator
object or a string that coerced into one, for which see L</LOCATOR STRINGS>.
The string you get from using the "Copy Secret Reference" feature of 1Password,
as long as the 1Password account is not ambiguous at runtime.

If the locator does not specify a field name, an exception will be raised.

It will return the string form of whatever is stored in that field.  If it
can't find the field, if it can't authenticate, or in any case other than
"everything worked", it will raise an exception.

=cut

sub get_field ($self, $locator) {
  $self->_call_op_read_for_field_ref($locator);
}

sub _call_op_read_for_field_ref ($self, $locator, $arg = {}) {
  unless (ref $locator) {
    $locator = Password::OnePassword::OPCLI::Locator->_from_string($locator);
  }

  unless (defined $locator->field) {
    Carp::croak("locator provided to get_field does not specify a field name");
  }

  my $url = $locator->_as_op_url;

  # I don't like this.  The problem, *in part*, is that you can't just pass the
  # op:// URI through URI.pm, because its ->as_string will encode spaces to
  # %20, but that isn't permitted in "op read".  This probably has a better
  # workaround, but the goal right now is just to make the method work.
  # -- rjbs, 2024-06-09
  if ($arg->{attribute}) {
    $url .= "?attribute=$arg->{attribute}";
  }

  my @op_command = (
    qw(op read),
    $url,
  );

  local $ENV{OP_ACCOUNT} = $locator->account // $ENV{OP_ACCOUNT};
  open(my $proc, '-|', @op_command) or Carp::croak("can't spawn op: $!");

  my $str = join q{}, <$proc>;

  # TODO: Log $? and $!, do something better. -- rjbs, 2024-05-03
  close($proc) or Carp::croak("problem running 'op read'");

  chomp $str;
  return $str;
}

=method get_otp

  my $otp = $one_pw->get_otp($locator);

This looks up an item in 1Password, using the C<op read> command.  The item is
assumed to be an OTP-type field.  Instead of returning the field's value, which
would be the TOTP secret, this method will return the one-time password for the
current time.

The C<$locator> argument works the same as the argument to the C<get_field>
method.

If C<op> can't find the field, if the field isn't an OTP field, if it can't
authenticate, or in any case other than "everything worked", the library will
raise an exception.

=cut

sub get_otp ($self, $locator) {
  $self->_call_op_read_for_field_ref($locator, {
    # This is stupid, see _call_op_read_for_field_ref.
    attribute => 'otp',
  });
}

=head1 LOCATOR STRINGS

1Password offers C<op://> URLs for fetching things via C<op>, but they're not
quite good enough, at least for this author's needs.  First off, if you use the
"Copy Secret Reference" feature of 1Password, you'll end up with a string like
this on your clipboard:

  op://Private/Super Mario Fan Club/password

This refers to a single I<field> in the vault item.  You can pass this to the
C<op read> command.  If you want to fetch the whole secret item, though, you
I<can't> just drop the third part of the path to pass to C<op item get>.  If
you have that URL and want to get the whole item, you need to parse it and
build a command-line invocation yourself.

There's a worse problem, too.  A two-part (item, not field) URL makes sense
because you just drop one piece of data from the three-part URL.  But these
URLs are also I<missing> a place for the account.  If you've got more than one
1Password account on your laptop, like both work and personal, you can't
unambiguously specify a credential with only a string.  This really undercuts
the value of the C<op://> URIs as (for example) environment variables.  You end
up having to set a I<second> environment variable indicating which account to
use, and if you need to access more than one vault in a program, the complexity
piles up.

Password::OnePassword::OPCLI works with "locator" objects, which the user
shouldn't really need to think about.  The user of the library can pass in a
string that can be parsed into a locator, either as a normal three-part
C<op://> URL, or as a bogus-but-comprehensible two-part URL, or as an
OPCLI-specific string like this:

  opcli:a=${Account}:v=${Vault}:i=${Item}:f=${Field}

Order is not important and only the item field is required.  To represent the
URL above (C<op://Private/Super Mario Fan Club/password>) in this format,
you'd write:

  opcli:v=Private:i=Super Mario Fan Club:f=password

Later, if you realized that you need to specify an account, you could tack it
on the end:

  opcli:v=Private:i=Super Mario Fan Club:f=password:a=Personal

=cut

package Password::OnePassword::OPCLI::Locator {
  use Moo;
  use v5.36.0;

  has account => (is => 'ro');
  has vault   => (is => 'ro');
  has item    => (is => 'ro');
  has field   => (is => 'ro');

  sub _as_op_url ($self) {
    return sprintf "op://%s/%s/%s",
      $self->vault // Carp::confess("tried to build op:// URL without vault name"),
      $self->item  // Carp::confess("tried to build op:// URL without item identifier"),
      $self->field // Carp::confess("tried to build op:// URL without field name");
  }

  sub _from_string ($class, $str) {
    my $account;
    my $vault;
    my $item;
    my $field;

    if ($str =~ m{\Aop://([^/]+)/([^/]+)(/([^/]*))?\z}) {
      $vault = $1;
      $item  = $2;
      $field = $3;
    } elsif ($str =~ m{\Aopcli:}) {
      # ...
    } else {
      $item = $str;
    }

    unless (length $item) {
      Carp::confess("empty item identifier in 1Password locator string");
    }

    return $class->new({
      account => $account,
      vault   => $vault,
      item    => $item,
      field   => $field,
    });
  }

  no Moo;
}

1;
