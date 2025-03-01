import { Entity, PrimaryGeneratedColumn, ManyToOne, Column, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Post } from '../../post/entities/post.entity';

@Entity('likes')
export class Like {
  @PrimaryGeneratedColumn()
  id: number; // This will be an INT by default

  @ManyToOne(() => User, (user) => user.likes, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Post, (post) => post.likes, { onDelete: 'CASCADE' })
  post: Post;

  // 2) Auto-manage creation, update, and soft-delete timestamps
  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  /**
   * When you add @DeleteDateColumn, TypeORM can use "soft delete" 
   * (the record is marked deleted but not physically removed).
   * If you call repository.softRemove(...), it sets the deletedAt value.
   */
  @DeleteDateColumn()
  deletedAt?: Date;
}
