package Password::OnePassword::OPCLI;
# ABSTRACT: get items out of 1Password with the "op" CLI

use v5.36.0;

use Carp ();
use IPC::Run qw(run timeout);
use JSON::MaybeXS qw(decode_json);

=head1 SYNOPSIS

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

  my $hashref = $one_pw->get_item($item_str, \%arg);

This looks up an item in 1Password, using the C<op item get> command.  The
locator C<$item_str> can be I<either> the item id I<or> two-part C<op://> URL.
The way the URL works is like this:  If you use the "Copy Secret Reference"
feature of 1Password, you'll end up with a string like this on your clipboard:

  op://Private/Super Mario Fan Club/password

This refers to a single I<field> in the vault item.  (You can get that field's
value with C<get_field>, below.)  You can't presently use a URL like this with
the C<op> command, but this library fakes it for you.  If you provide only the
first two path parts of the URL above, like this:

  op://Private/Super Mario Fan Club

…then C<get_item> will get the "Super Mario Fan Club" item out of the "Private"
vault.

The reference to a C<%arg> hash is optional.  If given, it can contain a
C<vault> entry, giving the name of the vault to look in.  This is only useful
when giving an item id, rather than a URL.

The method returns a reference to a hash in 1Password's documented internal
format.  For more information, consult the 1Password developer tools
documentation.  Alternatively, use this method and pretty-print the results.

If the item can't be found, or the C<op> command doesn't exit zero, or in any
case other than the best case, this method will throw an exception.

=cut

sub get_item ($self, $item_str, $arg={}) {
  my $vault = $arg->{vault};

  unless (length $item_str) {
    Carp::croak('required argument $item_str was empty');
  }

  my $item;

  if ($item_str =~ m{\Aop://([^/]+)/([^/]+)/?\z}) {
    $vault = $1;
    $item  = $2;
  } elsif ($item_str =~ m{\Aop:}) {
    Carp::croak("The given item id looks like an op: URL, but isn't in the format op://VAULT/ITEM");
  } else {
    $item = $item_str;
  }

  my @op_command = (
    qw(op item get),
    (length $vault ? ('--vault', $vault) : ()),
    ('--format', 'json'),
    $item,
  );

  open(my $proc, '-|', @op_command) or Carp::croak("can't spawn op: $!");

  my $json = join q{}, <$proc>;

  # TODO: Log $? and $!, do something better. -- rjbs, 2024-05-03
  close($proc) or Carp::croak("problem running 'op item get'");

  return decode_json($json);
}

=method get_field

  my $str = $one_pw->get_field($field_ref_str);

This looks up an item in 1Password, using the C<op read> command.  The locator
C<$field_ref_str> should be an C<op://> URL, like you'd get using the "Copy
Secret Reference" feature of 1Password.

It will return the string form of whatever is stored in that field.  If it
can't find the field, if it can't authenticate, or in any case other than
"everything worked", it will raise an exception.

=cut

sub get_field ($self, $field_ref_str) {
  $self->_call_op_read_for_field_ref($field_ref_str);
}

sub _call_op_read_for_field_ref ($self, $field_ref_str, $arg = {}) {
  unless (length $field_ref_str) {
    Carp::croak('required argument $field_ref_str was empty');
  }

  unless ($field_ref_str =~ m{\Aop://}) {
    Carp::croak('$field_ref_str does not appear to be an op:// URL');
  }

  # I don't like this.  The problem, *in part*, is that you can't just pass the
  # op:// URI through URI.pm, because its ->as_string will encode spaces to
  # %20, but that isn't permitted in "op read".  This probably has a better
  # workaround, but the goal right now is just to make the method work.
  # -- rjbs, 2024-06-09
  if ($arg->{attribute}) {
    $field_ref_str .= "?attribute=$arg->{attribute}";
  }

  my @op_command = (
    qw(op read),
    $field_ref_str,
  );

  open(my $proc, '-|', @op_command) or Carp::croak("can't spawn op: $!");

  my $str = join q{}, <$proc>;

  # TODO: Log $? and $!, do something better. -- rjbs, 2024-05-03
  close($proc) or Carp::croak("problem running 'op read'");

  chomp $str;
  return $str;
}

=method get_otp

  my $otp = $one_pw->get_otp($field_ref_str);

This looks up an item in 1Password, using the C<op read> command.  The item is
assumed to be an OTP-type field.  Instead of returning the field's value, which
would be the TOTP secret, this method will return the one-time password for the
current time.

If it can't find the field, if the field isn't an OTP field, if it can't
authenticate, or in any case other than "everything worked", the library will
raise an exception.

=cut

sub get_otp ($self, $field_ref_str) {
  $self->_call_op_read_for_field_ref($field_ref_str, {
    # This is stupid, see _call_op_read_for_field_ref.
    attribute => 'otp',
  });
}

1;
