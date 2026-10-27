"""
RETIRED - the router self-play win-mining loop (Step 8).

This loop used to: play router-driven battles, mine every *winning* battle
into a training example labeled with the technique that won, then retrain.
That labeling was unreliable - some targets satisfy more than one technique's
success check, so wins got attributed to the wrong technique (e.g. a
broken_auth target also "wins" for sql_injection, since its login issues a
token to anyone). Training on those false labels is what taught the router to
guess instead of reading recon clues.

The router dataset is now built deterministically from GROUND TRUTH instead
(each target labeled with the vulnerability it actually has, from
training/targets.py), which cannot mislabel. There is no battle-mining step
anymore, so this loop no longer exists. The replacement is two commands:

  python -m agents.red_team.router.build_router_dataset   # clean, balanced, ground-truth data
  python -m agents.red_team.router.train_router           # train the adapter on it

See agents/red_team/router/build_router_dataset.py for the full rationale.
This stub is kept (rather than deleted) so running the old command gives a
clear pointer instead of a confusing ModuleNotFoundError.
"""

import sys

_MESSAGE = __doc__.strip()


def run_loop(*args, **kwargs):
    raise RuntimeError(
        "router_battle_loop is retired - its win-mining produced mislabeled training examples. "
        "Build the router dataset from ground truth instead:\n"
        "  python -m agents.red_team.router.build_router_dataset\n"
        "  python -m agents.red_team.router.train_router"
    )


if __name__ == "__main__":
    print(_MESSAGE, file=sys.stderr)
    sys.exit(1)
