/*
 * Copyright (c) 2024-present, arana-db Community.  All rights reserved.
 * 
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::options::StorageOptions;

pub struct Storage;
pub struct DB {
    db_index: i32,
    db_path: String,
    storage: Arc<RwLock<Option<Box<Storage>>>>,
    opened: bool,
}
impl DB {
    pub fn new(db_index: i32, db_path: String) -> DB {
        DB {
            db_index,
            db_path,
            storage: Arc::new(RwLock::new(None)),
            opened: false,
        }
    }

    pub fn open(&mut self) -> Result<(), ()> {
        let mut storage_options = StorageOptions::default();

        // TODO: configure by conf file
        storage_options.set_db_instance_num(1);
        storage_options.set_db_id(self.db_index);

        // TODO: storage implement
        // let mut storage = Storage::default();

        Ok(())
    }

    pub fn get_storage(&self) -> RwLockReadGuard<Option<Box<Storage>>> {
        self.storage.read().unwrap()
    }

    pub fn lock(&self) -> RwLockWriteGuard<Option<Box<Storage>>> {
        self.storage.write().unwrap()
    }

    pub fn create_checkpoint(&self, path: &str, sync: bool) {
        // TODO: creating database checkpoints
    }

    pub fn load_db_from_checkpoint(&self, path: &str, sync: bool) {
        // TODO: loading a database from a checkpoint
    }

    pub fn get_db_index(&self) -> i32 {
        self.db_index
    }
}
