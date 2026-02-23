forge coverage --report lcov

lcov --ignore-errors unused --remove ./lcov.info \
  '*/test/*' \
  '*test*.sol' \
  '*/script/*' \
  '*/mocks/*' \
  -o ./lcov.info.pruned

genhtml lcov.info.pruned --output-directory coverage

open coverage/index.html