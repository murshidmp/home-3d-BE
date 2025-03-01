import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Post } from '../../post/entities/post.entity';

@Entity('comments')
export class Comment {
  @PrimaryGeneratedColumn()
  id: number; // This will be an INT by default

  @ManyToOne(() => User, (user) => user.comments, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Post, (post) => post.comments, { onDelete: 'CASCADE' })
  post: Post;

  @Column()
  content: string;

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
