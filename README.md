This is a collection of Ruby classes which implement all of the fundamental
data types described in [RFC6962](http://tools.ietf.org/html/rfc6962).

At present, it is not feature complete, however what is released is well
tested, heavily documented, and should be ready for production use.


# Installation

It's a gem:

    gem install certificate-transparency

There's also the wonders of [the Gemfile](http://bundler.io):

    gem 'certificate-transparency'

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


# Usage

You'll probably want a good working knowledge of the data types in
[RFC6962](http://tools.ietf.org/html/rfc6962) to make any sense of this gem.

All the classes are under the `CT` namespace (or you can use the full
version, `CertificateTransparency`, if you're feeling like doing a lot of
typing).  The class names are all the same names as provided in the RFC.

In general, a data type will implement some combination of the following
methods:

* `.from_json` -- read the data structure from the JSON that would be
  returned by the relevant request to a CT log server.

* `#to_json` -- spew out a JSON document which represents the data
  structure.

* `.from_blob` -- parse a binary blob to obtain the fields of the data
  structure.

* `#to_blob` -- encode the data structure into a binary blob.

You can also generate an empty data structure by calling `.new` on the
class.  Read and write accessors for all the field names (matching the names
given in the RFC) are available.  If you attempt to call a `#to_*` method
without having filled out all the fields, a `CT::IncompleteDataError` will
be returned.

If a field is an `enum`, then a symbol is expected to come in and out,
not the numeric value.  If the field is a `timestamp`, a `Time` instance is
expected.


# Contributing

Bug reports should be sent to the [Github issue
tracker](https://github.com/mpalmer/certificate-transparency/issues),
or [e-mailed](mailto:theshed+certificate-transparency@hezmatt.org). 
Patches can be sent as a Github pull request, or
[e-mailed](mailto:theshed+certificate-transparency@hezmatt.org).


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2014,2015  Matt Palmer <matt@hezmatt.org>

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
