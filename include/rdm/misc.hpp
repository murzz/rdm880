#pragma once

#include <iterator>
#include <cstdint>

static const int default_len_value = -1;

template<typename container_type>
container_type mid(const container_type & container, const typename container_type::size_type pos,
      typename container_type::difference_type len = typename container_type::difference_type(default_len_value))
{
   auto begin = container.end();
   auto end = container.end();

   if (std::distance(container.begin(), container.end()) > static_cast<typename container_type::difference_type>(pos))
   {
      begin = std::next(container.begin(), pos);
   }

   if ((default_len_value != len) && (std::distance(begin, container.end()) > len))
   {
      end = std::next(begin, len);
   }

   return container_type(begin, end);
}

template<typename E>
constexpr auto to_integral(E e) -> typename std::underlying_type<E>::type
{
   return static_cast<typename std::underlying_type<E>::type>(e);
}

