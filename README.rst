ed25519
=======

.. image:: https://travis-ci.org/dstufft/ed25519.png?branch=master
   :target: https://travis-ci.org/dstufft/ed25519


`Ed25519 <http://ed25519.cr.yp.to/>`_ is a high speed public key signature
system. ed25519.py is the reference implementation that has been optimized
for a faster runtime. It does not include protections against side channel
attacks. The original reference implementation can be found on the
`authors website <http://ed25519.cr.yp.to/software.html>`_.


Warning
-------

This code is almost never what you want. It is hopefully useful in cases
where you absolutely cannot have any C code dependencies. Unless you
absolutely cannot have C code dependencies you would be better off using
something like `PyNaCl <https://github.com/dstufft/pynacl>`_.


Running the tests
-----------------

ed25519.py uses tox to run the test suite. You can run all the tests by using:

.. code:: bash

    $ tox


Resources
---------

* `IRC <http://webchat.freenode.net?channels=%23cryptography-dev>`_
  (#cryptography-dev - irc.freenode.net)
