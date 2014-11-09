import argparse


def make_argument_parser(db_path):
    parser = argparse.ArgumentParser(
        description='Migrate the database',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--path',
        default=db_path,
        help='the location of the database'
    )
    parser.add_argument(
        'action',
        choices=('upgrade', 'downgrade'),
        default='upgrade',
        help='the action you want to perform'
    )

    return parser
