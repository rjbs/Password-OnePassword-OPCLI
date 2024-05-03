package Password::OnePassword::OPCLI;
# ABSTRACT: get items out of 1Password with the "op" CLI

use v5.36.0;

use Carp ();
use IPC::Run qw(run timeout);
use JSON::MaybeXS qw(decode_json);

# args:
#   item - id or 2-part URL
#   vault (optional)
sub get_item ($self, $item, $arg={}) {
  my $vault = $arg->{vault};

  unless (length $item) {
    Carp::croak("required argument 'item' was empty");
  }

  if ($item =~ m{\Aop://([^/]+)/([^/]+)/?\z}) {
    $vault = $1;
    $item  = $2;
  } elsif ($item =~ m{\Aop:}) {
    Carp::croak("The given item id looks like an op: URL, but isn't in the format op://VAULT/ITEM");
  }

  my @op_command = (
    qw(op item get),
    (length $vault ? ('--vault', $vault) : ()),
    ('--format', 'json'),
    $item,
  );

  open(my $proc, '-|', @op_command) or Carp::croak("can't spawn op: $!");

  my $json = <$proc>;

  # TODO: Log $? and $!, do something better. -- rjbs, 2024-05-03
  close($proc) or Carp::croak("problem running $proc");

  return decode_json($json);
}

1;
