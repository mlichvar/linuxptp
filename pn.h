/**
 * @file pn.h
 * @brief Implements transport over PN.
 * @note Derived from raw.h.
 * Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef HAVE_PN_H
#define HAVE_PN_H

#include "transport.h"

/**
 * Allocate an instance of a PN Ethernet transport.
 * @return Pointer to a new transport instance on success, NULL otherwise.
 */
struct transport *pn_transport_create(void);

#endif
