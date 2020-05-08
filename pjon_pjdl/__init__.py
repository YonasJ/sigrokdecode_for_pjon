##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2012 Uwe Hermann <uwe@hermann-uwe.de>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

'''
https://www.pjon.org/

PJDL (Padded Jittering Data Link) is an asynchronous serial data link for low-data-rate
applications that supports both master-slave and multi-master communication over a common
conductive medium. PJDL can be easily implemented on limited microcontrollers with low
clock accuracy and can operate directly using a single input-output pin.

'''

from .pd import Decoder
