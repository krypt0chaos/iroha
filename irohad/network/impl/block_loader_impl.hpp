/**
 * Copyright Soramitsu Co., Ltd. 2017 All Rights Reserved.
 * http://soramitsu.co.jp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IROHA_BLOCK_LOADER_IMPL_HPP
#define IROHA_BLOCK_LOADER_IMPL_HPP

#include <unordered_map>

#include "loader.grpc.pb.h"
#include "model/converters/pb_block_factory.hpp"
#include "network/block_loader.hpp"

namespace iroha {
  namespace network {
    class BlockLoaderImpl : public BlockLoader {
     public:
      rxcpp::observable<model::Block> requestBlocks(
          model::Peer target_peer, model::Block topBlock) override;

     private:
      /**
       * Get or create a RPC stub for connecting to peer
       * @param peer for connecting
       * @return RPC stub
       */
      proto::Loader::Stub &getPeerStub(const model::Peer &peer);

      model::converters::PbBlockFactory factory_;
      std::unordered_map<model::Peer, std::unique_ptr<proto::Loader::Stub>>
          peer_connections_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_BLOCK_LOADER_IMPL_HPP