import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Project } from '../../project/entities/project.entity';
import { Like } from '../../like/entities/like.entity';
import { Comment } from '../../comment/entities/comment.entity';
import { Bookmark } from '../../bookmark/entities/bookmark.entity';

@Entity('posts')
export class Post {
  @PrimaryGeneratedColumn()
  id: number; // This will be an INT by default

  @ManyToOne(() => User, (user) => user.posts, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Project, (project) => project.posts, { nullable: true })
  project: Project;

  @Column()
  imageUrl: string;

  @Column({ nullable: true })
  description: string;

  @Column({ default: 0 })
  likeCount: number;

  @Column({ default: 0 })
  commentCount: number;

  @Column({ default: false })
  isTrending: boolean;

  @OneToMany(() => Like, (like) => like.post)
  likes: Like[];

  @OneToMany(() => Comment, (comment) => comment.post)
  comments: Comment[];

  @OneToMany(() => Bookmark, (bookmark) => bookmark.post)
  bookmarks: Bookmark[];

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
