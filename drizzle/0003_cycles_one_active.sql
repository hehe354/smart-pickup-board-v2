CREATE UNIQUE INDEX IF NOT EXISTS `cycles_one_active_per_restaurant`
ON `cycles` (`restaurant_id`)
WHERE `status` = 'active';
